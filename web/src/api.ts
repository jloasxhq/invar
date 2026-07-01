// Typed client for the forge-backend REST API.

export interface TokenInfo {
  name: string;
  symbol: string;
  decimals: number;
  total_supply: number;
  attested_reserve: number;
  paused: boolean;
}

export interface BalanceInfo {
  id: string;
  balance: number;
}

export interface LedgerEntry {
  id: string;
  kind: string;
  from: string | null;
  to: string | null;
  amount: number;
  as_of_unix: number;
}

export class ForgeClient {
  constructor(private base: string) {}

  private url(path: string): string {
    return this.base.replace(/\/$/, "") + path;
  }

  private async req<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await fetch(this.url(path), {
      method,
      headers: body !== undefined ? { "Content-Type": "application/json" } : {},
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`${res.status} ${text}`);
    return (text ? JSON.parse(text) : undefined) as T;
  }

  token(): Promise<TokenInfo> {
    return this.req<TokenInfo>("GET", "/token");
  }
  account(id: string): Promise<BalanceInfo> {
    return this.req<BalanceInfo>("GET", "/accounts/" + id);
  }
  entries(): Promise<LedgerEntry[]> {
    return this.req<LedgerEntry[]>("GET", "/entries");
  }
  onboard(id: string): Promise<void> {
    return this.req<void>("POST", "/accounts", { id });
  }
  kyc(id: string, verified: boolean): Promise<void> {
    return this.req<void>("POST", `/accounts/${id}/kyc`, { verified });
  }
  attest(reserve: number, custodianRef: string): Promise<unknown> {
    return this.req<unknown>("POST", "/attest", { reserve, custodian_ref: custodianRef });
  }
  mint(to: string, amount: number): Promise<void> {
    return this.req<void>("POST", "/mint", { to, amount });
  }
  transfer(from: string, to: string, amount: number): Promise<void> {
    return this.req<void>("POST", "/transfer", { from, to, amount });
  }
  hold(from: string, amount: number, beneficiary?: string): Promise<{ id: string }> {
    return this.req<{ id: string }>("POST", "/holds", { from, amount, beneficiary });
  }
}
