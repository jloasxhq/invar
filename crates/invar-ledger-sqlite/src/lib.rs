//! # invar-ledger-sqlite
//!
//! A durable [`LedgerPort`] backed by SQLite. Unlike the in-memory/JSON-snapshot
//! custodial adapter, this persists **every** write immediately with ACID semantics:
//!
//! - **WAL journaling** (`PRAGMA journal_mode=WAL`) for crash durability and
//!   concurrent readers; a `Mutex<Connection>` serializes writers.
//! - **Append-only entry log** (`entries` is INSERT-only — never updated or deleted),
//!   the raw material for an audit trail / PQC transparency log.
//! - Balances, supply, reserve, holds, and the **governance blob** (roles/KYC/pause/
//!   allowances) all survive a process restart — reopen the same file and the full
//!   state is intact.
//!
//! `u128` amounts are stored as decimal TEXT (SQLite integers are 64-bit). Per-write
//! atomicity is provided; wrapping a multi-step domain operation (e.g. mint =
//! balance + supply + entry) in a single transaction is a further hardening step
//! (see docs/ROADMAP.md).

use std::path::Path;
use std::sync::Mutex;

use invar_core::account::{Account, AccountId};
use invar_core::amount::Amount;
use invar_core::error::{InvarError, Result};
use invar_core::hold::Hold;
use invar_core::ledger::{LedgerEntry, LedgerPort};
use rusqlite::{params, Connection, OptionalExtension};

const SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS accounts (
    id      TEXT PRIMARY KEY,
    balance TEXT NOT NULL,
    frozen  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS kv (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    id         TEXT NOT NULL,
    kind       TEXT NOT NULL,
    from_id    TEXT,
    to_id      TEXT,
    amount     TEXT NOT NULL,
    as_of_unix INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS holds (
    id           TEXT PRIMARY KEY,
    from_id      TEXT NOT NULL,
    beneficiary  TEXT,
    amount       TEXT NOT NULL,
    expires_unix INTEGER NOT NULL,
    status       TEXT NOT NULL,
    created_unix INTEGER NOT NULL
);
"#;

/// Durable SQLite-backed ledger.
pub struct SqliteLedger {
    conn: Mutex<Connection>,
}

fn db<E: std::fmt::Display>(e: E) -> InvarError {
    InvarError::Ledger(e.to_string())
}

fn parse_u128(s: &str) -> Result<u128> {
    s.parse::<u128>().map_err(db)
}

impl SqliteLedger {
    /// Open (or create) a database at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::init(Connection::open(path).map_err(db)?)
    }

    /// An in-memory database (non-durable — for tests).
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory().map_err(db)?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(SCHEMA).map_err(db)?;
        conn.execute(
            "INSERT OR IGNORE INTO kv(key, value) VALUES('supply', ?1)",
            params![b"0".to_vec()],
        )
        .map_err(db)?;
        conn.execute(
            "INSERT OR IGNORE INTO kv(key, value) VALUES('reserve', ?1)",
            params![b"0".to_vec()],
        )
        .map_err(db)?;
        Ok(SqliteLedger {
            conn: Mutex::new(conn),
        })
    }

    fn get_amount(&self, key: &str) -> Result<Amount> {
        let conn = self.conn.lock().unwrap();
        let v: Vec<u8> = conn
            .query_row("SELECT value FROM kv WHERE key=?1", params![key], |r| {
                r.get(0)
            })
            .map_err(db)?;
        Ok(Amount::new(parse_u128(&String::from_utf8(v).map_err(db)?)?))
    }

    fn set_amount(&self, key: &str, amount: Amount) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO kv(key, value) VALUES(?1, ?2)",
            params![key, amount.get().to_string().into_bytes()],
        )
        .map_err(db)?;
        Ok(())
    }
}

impl LedgerPort for SqliteLedger {
    fn is_registered(&self, id: &AccountId) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM accounts WHERE id=?1",
                params![id.as_str()],
                |r| r.get(0),
            )
            .map_err(db)?;
        Ok(n > 0)
    }

    fn register(&self, id: &AccountId) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO accounts(id, balance, frozen) VALUES(?1, '0', 0)",
            params![id.as_str()],
        )
        .map_err(db)?;
        Ok(())
    }

    fn account(&self, id: &AccountId) -> Result<Account> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT balance, frozen FROM accounts WHERE id=?1",
                params![id.as_str()],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(db)?;
        match row {
            Some((balance, frozen)) => Ok(Account {
                id: id.clone(),
                balance: Amount::new(parse_u128(&balance)?),
                frozen: frozen != 0,
            }),
            None => Err(InvarError::UnknownAccount(id.to_string())),
        }
    }

    fn set_account(&self, account: &Account) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO accounts(id, balance, frozen) VALUES(?1, ?2, ?3)",
            params![
                account.id.as_str(),
                account.balance.get().to_string(),
                account.frozen as i64
            ],
        )
        .map_err(db)?;
        Ok(())
    }

    fn total_supply(&self) -> Result<Amount> {
        self.get_amount("supply")
    }
    fn set_total_supply(&self, supply: Amount) -> Result<()> {
        self.set_amount("supply", supply)
    }
    fn attested_reserve(&self) -> Result<Amount> {
        self.get_amount("reserve")
    }
    fn set_attested_reserve(&self, reserve: Amount) -> Result<()> {
        self.set_amount("reserve", reserve)
    }

    fn append_entry(&self, entry: &LedgerEntry) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO entries(id, kind, from_id, to_id, amount, as_of_unix) \
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                entry.id,
                serde_json::to_string(&entry.kind).map_err(db)?,
                entry.from.as_ref().map(|a| a.as_str()),
                entry.to.as_ref().map(|a| a.as_str()),
                entry.amount.get().to_string(),
                entry.as_of_unix as i64,
            ],
        )
        .map_err(db)?;
        Ok(())
    }

    fn entries(&self) -> Result<Vec<LedgerEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, kind, from_id, to_id, amount, as_of_unix FROM entries ORDER BY seq",
            )
            .map_err(db)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                ))
            })
            .map_err(db)?;
        let mut out = Vec::new();
        for row in rows {
            let (id, kind, from_id, to_id, amount, as_of) = row.map_err(db)?;
            out.push(LedgerEntry {
                id,
                kind: serde_json::from_str(&kind).map_err(db)?,
                from: from_id.map(AccountId::new),
                to: to_id.map(AccountId::new),
                amount: Amount::new(parse_u128(&amount)?),
                as_of_unix: as_of as u64,
            });
        }
        Ok(out)
    }

    fn put_hold(&self, hold: &Hold) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO holds(id, from_id, beneficiary, amount, expires_unix, status, created_unix) \
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                hold.id,
                hold.from.as_str(),
                hold.beneficiary.as_ref().map(|a| a.as_str()),
                hold.amount.get().to_string(),
                hold.expires_unix as i64,
                serde_json::to_string(&hold.status).map_err(db)?,
                hold.created_unix as i64,
            ],
        )
        .map_err(db)?;
        Ok(())
    }

    fn get_hold(&self, id: &str) -> Result<Hold> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT from_id, beneficiary, amount, expires_unix, status, created_unix FROM holds WHERE id=?1",
                params![id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(db)?;
        match row {
            Some((from_id, beneficiary, amount, expires, status, created)) => Ok(Hold {
                id: id.to_string(),
                from: AccountId::new(from_id),
                beneficiary: beneficiary.map(AccountId::new),
                amount: Amount::new(parse_u128(&amount)?),
                expires_unix: expires as u64,
                status: serde_json::from_str(&status).map_err(db)?,
                created_unix: created as u64,
            }),
            None => Err(InvarError::HoldNotFound(id.to_string())),
        }
    }

    fn holds(&self) -> Result<Vec<Hold>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, from_id, beneficiary, amount, expires_unix, status, created_unix FROM holds")
            .map_err(db)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, i64>(6)?,
                ))
            })
            .map_err(db)?;
        let mut out = Vec::new();
        for row in rows {
            let (id, from_id, beneficiary, amount, expires, status, created) = row.map_err(db)?;
            out.push(Hold {
                id,
                from: AccountId::new(from_id),
                beneficiary: beneficiary.map(AccountId::new),
                amount: Amount::new(parse_u128(&amount)?),
                expires_unix: expires as u64,
                status: serde_json::from_str(&status).map_err(db)?,
                created_unix: created as u64,
            });
        }
        Ok(out)
    }

    fn load_governance(&self) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT value FROM kv WHERE key='governance'", [], |r| {
            r.get::<_, Vec<u8>>(0)
        })
        .optional()
        .map_err(db)
    }

    fn save_governance(&self, data: &[u8]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO kv(key, value) VALUES('governance', ?1)",
            params![data],
        )
        .map_err(db)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use invar_core::{Allowance, CryptoProvider, KycStatus, Role, StablecoinService, TokenConfig};
    use invar_crypto::FipsPqcProvider;

    fn temp_db(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("invar_sqlite_{name}.db"));
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{}", p.display(), suffix));
        }
        p
    }

    /// The heart of the durability guarantee: run a flow, drop everything, reopen the
    /// same file, and confirm BOTH the ledger AND governance (roles/KYC/allowances)
    /// survived — the exact gap the analysis flagged.
    #[test]
    fn survives_restart_ledger_and_governance() {
        let path = temp_db("restart");
        let admin = AccountId::new("issuer");
        let bob = AccountId::new("bob");

        {
            let ledger = SqliteLedger::open(&path).unwrap();
            let svc = StablecoinService::new(
                TokenConfig::new("Generic USD", "gUSD", 2),
                ledger,
                FipsPqcProvider::new(),
                admin.clone(),
            )
            .unwrap();
            // Governance mutations (persisted through the port):
            svc.register_account(&admin, &bob).unwrap();
            svc.set_kyc(&admin, &bob, KycStatus::Verified).unwrap();
            svc.grant_role(&admin, &bob, Role::Minter).unwrap();
            svc.set_supply_allowance(&admin, &bob, Allowance::Limited(Amount::new(1000)))
                .unwrap();
            // Ledger mutations:
            svc.set_reserve(&admin, Amount::new(10_000)).unwrap();
            svc.mint(&admin, &bob, Amount::new(500)).unwrap();
        } // service + connection dropped == process "restart"

        // Reopen from the SAME file with a fresh service.
        let ledger = SqliteLedger::open(&path).unwrap();
        let svc = StablecoinService::new(
            TokenConfig::new("Generic USD", "gUSD", 2),
            ledger,
            FipsPqcProvider::new(),
            admin.clone(),
        )
        .unwrap();

        // Ledger survived:
        assert_eq!(svc.balance_of(&bob).unwrap(), Amount::new(500));
        assert_eq!(svc.total_supply().unwrap(), Amount::new(500));
        assert_eq!(svc.attested_reserve().unwrap(), Amount::new(10_000));
        assert!(!svc.entries().unwrap().is_empty());

        // Governance survived (allowance is directly observable):
        assert_eq!(
            svc.allowance_of(&bob),
            Some(Allowance::Limited(Amount::new(1000)))
        );

        // And behaviourally: bob still has Minter + KYC + allowance after restart,
        // so he can mint (consuming 300 of his 1000 allowance).
        svc.mint(&bob, &bob, Amount::new(300)).unwrap();
        assert_eq!(svc.balance_of(&bob).unwrap(), Amount::new(800));
        assert_eq!(
            svc.allowance_of(&bob),
            Some(Allowance::Limited(Amount::new(700)))
        );

        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{}", path.display(), suffix));
        }
    }

    #[test]
    fn entries_are_append_only_and_ordered() {
        let ledger = SqliteLedger::open_in_memory().unwrap();
        let svc = StablecoinService::new(
            TokenConfig::new("T", "T", 2),
            ledger,
            FipsPqcProvider::new(),
            AccountId::new("admin"),
        )
        .unwrap();
        let admin = AccountId::new("admin");
        let a = AccountId::new("a");
        svc.register_account(&admin, &a).unwrap();
        svc.set_kyc(&admin, &a, KycStatus::Verified).unwrap();
        svc.set_reserve(&admin, Amount::new(1_000_000)).unwrap();
        let (vk, sk) = svc.crypto().generate_keypair().unwrap();
        svc.attest_reserve(&admin, &vk, &sk, Amount::new(1_000_000), "bank")
            .unwrap();
        svc.mint(&admin, &a, Amount::new(100)).unwrap();
        svc.mint(&admin, &a, Amount::new(50)).unwrap();
        let entries = svc.entries().unwrap();
        // Two mints appended, in order (append-only log grows, never mutates).
        let mints: Vec<_> = entries
            .iter()
            .filter(|e| format!("{:?}", e.kind) == "Mint")
            .collect();
        assert_eq!(mints.len(), 2);
        assert_eq!(mints[0].amount, Amount::new(100));
        assert_eq!(mints[1].amount, Amount::new(50));
    }
}
