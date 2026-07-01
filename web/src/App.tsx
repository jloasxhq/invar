import { useCallback, useMemo, useState } from "react";
import { InvarClient, LedgerEntry, TokenInfo } from "./api";

const cardStyle: React.CSSProperties = {
  background: "#171a21",
  border: "1px solid #2a2f3a",
  borderRadius: 10,
  padding: "1rem 1.25rem",
  margin: "1rem 0",
  maxWidth: 720,
};
const inputStyle: React.CSSProperties = {
  fontSize: ".95rem",
  padding: ".4rem .5rem",
  borderRadius: 6,
  border: "1px solid #2a2f3a",
  background: "#0f1115",
  color: "#e6e6e6",
  margin: "0 .4rem .4rem 0",
};
const btnStyle: React.CSSProperties = {
  ...inputStyle,
  background: "#2d6cdf",
  border: "none",
  cursor: "pointer",
};

export default function App() {
  const [base, setBase] = useState("http://127.0.0.1:8080");
  const [log, setLog] = useState<string>("(no actions yet)");
  const [token, setToken] = useState<TokenInfo | null>(null);
  const [entries, setEntries] = useState<LedgerEntry[]>([]);

  const client = useMemo(() => new InvarClient(base), [base]);

  const run = useCallback(
    async (label: string, fn: () => Promise<unknown>) => {
      try {
        const result = await fn();
        setLog(`✓ ${label}` + (result ? `: ${JSON.stringify(result)}` : ""));
      } catch (e) {
        setLog(`✗ ${label}: ${e instanceof Error ? e.message : String(e)}`);
      }
    },
    [],
  );

  const refresh = useCallback(async () => {
    await run("token", async () => {
      const t = await client.token();
      setToken(t);
      return t;
    });
    try {
      setEntries(await client.entries());
    } catch {
      /* ignore entries error on refresh */
    }
  }, [client, run]);

  // Simple controlled fields via a single record.
  const [f, setF] = useState<Record<string, string>>({});
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setF((prev) => ({ ...prev, [k]: e.target.value }));
  const num = (k: string) => Number(f[k] ?? "0");

  return (
    <div style={{ fontFamily: "system-ui, sans-serif", margin: "2rem", color: "#e6e6e6", background: "#0f1115" }}>
      <h1 style={{ fontSize: "1.35rem" }}>
        invar <span style={{ color: "#9aa4b2", fontSize: "1rem" }}>operator dashboard</span>
      </h1>

      <div style={cardStyle}>
        <label style={{ color: "#9aa4b2", fontSize: ".8rem" }}>API base URL</label>
        <div>
          <input style={{ ...inputStyle, width: 300 }} value={base} onChange={(e) => setBase(e.target.value)} />
          <button style={btnStyle} onClick={refresh}>Refresh</button>
        </div>
        {token && (
          <table style={{ marginTop: ".5rem", fontSize: ".9rem" }}>
            <tbody>
              <tr><td style={{ color: "#9aa4b2", paddingRight: 12 }}>token</td><td>{token.name} ({token.symbol}, {token.decimals}dp)</td></tr>
              <tr><td style={{ color: "#9aa4b2" }}>supply</td><td>{token.total_supply}</td></tr>
              <tr><td style={{ color: "#9aa4b2" }}>reserve</td><td>{token.attested_reserve}</td></tr>
              <tr><td style={{ color: "#9aa4b2" }}>paused</td><td>{String(token.paused)}</td></tr>
            </tbody>
          </table>
        )}
      </div>

      <div style={cardStyle}>
        <b>Onboard &amp; verify</b>
        <div style={{ marginTop: ".5rem" }}>
          <input style={inputStyle} placeholder="account id" value={f.onboardId ?? ""} onChange={set("onboardId")} />
          <button style={btnStyle} onClick={() => run("onboard", () => client.onboard(f.onboardId ?? ""))}>Onboard</button>
          <button style={btnStyle} onClick={() => run("kyc verify", () => client.kyc(f.onboardId ?? "", true))}>Verify KYC</button>
        </div>
      </div>

      <div style={cardStyle}>
        <b>Reserve &amp; mint</b>
        <div style={{ marginTop: ".5rem" }}>
          <input style={inputStyle} placeholder="reserve (minor units)" value={f.reserve ?? ""} onChange={set("reserve")} />
          <input style={inputStyle} placeholder="custodian ref" value={f.ref ?? ""} onChange={set("ref")} />
          <button style={btnStyle} onClick={() => run("attest", () => client.attest(num("reserve"), f.ref ?? ""))}>Attest (PQC)</button>
        </div>
        <div>
          <input style={inputStyle} placeholder="mint to" value={f.mintTo ?? ""} onChange={set("mintTo")} />
          <input style={inputStyle} placeholder="amount" value={f.mintAmt ?? ""} onChange={set("mintAmt")} />
          <button style={btnStyle} onClick={() => run("mint", () => client.mint(f.mintTo ?? "", num("mintAmt")))}>Mint</button>
        </div>
      </div>

      <div style={cardStyle}>
        <b>Transfer &amp; hold</b>
        <div style={{ marginTop: ".5rem" }}>
          <input style={inputStyle} placeholder="from" value={f.txFrom ?? ""} onChange={set("txFrom")} />
          <input style={inputStyle} placeholder="to" value={f.txTo ?? ""} onChange={set("txTo")} />
          <input style={inputStyle} placeholder="amount" value={f.txAmt ?? ""} onChange={set("txAmt")} />
          <button style={btnStyle} onClick={() => run("transfer", () => client.transfer(f.txFrom ?? "", f.txTo ?? "", num("txAmt")))}>Transfer</button>
          <button style={btnStyle} onClick={() => run("hold", () => client.hold(f.txFrom ?? "", num("txAmt"), f.txTo || undefined))}>Hold</button>
        </div>
      </div>

      <div style={cardStyle}>
        <b>Last action</b>
        <pre style={{ background: "#0b0d11", padding: ".6rem", borderRadius: 6, whiteSpace: "pre-wrap" }}>{log}</pre>
      </div>

      <div style={cardStyle}>
        <b>Ledger entries ({entries.length})</b>
        <pre style={{ background: "#0b0d11", padding: ".6rem", borderRadius: 6, maxHeight: 220, overflow: "auto", fontSize: ".8rem" }}>
          {entries.map((e) => `${e.kind.padEnd(12)} ${e.from ?? "-"} → ${e.to ?? "-"}  ${e.amount}`).join("\n") || "(none)"}
        </pre>
      </div>
    </div>
  );
}
