// Command forge-cli is the operator client for stablecoin-forge. It talks to the
// forge-backend REST API. Build and run it under the Go FIPS module for a
// validated transport boundary:
//
//	GODEBUG=fips140=on go run ./cli -url http://127.0.0.1:8080 token
//
// Standard library only (net/http, encoding/json) — no third-party dependencies.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

const usage = `forge-cli — stablecoin-forge operator client

usage: forge-cli [-url BASE] [-insecure] <command> [args]
  -url BASE    API base (default https://127.0.0.1:8443)
  -insecure    skip TLS certificate verification (dev/self-signed only)

commands:
  token                          show token config, supply, reserve
  onboard <id>                   register (KYB) an account
  kyc <id> <true|false>          set verification status
  mint <to> <amount>             mint units (subject to reserve peg)
  burn <from> <amount>           burn units from an account
  transfer <from> <to> <amount>  move units between holders
  redeem <from> <amount>         burn units after fiat cash-out
  pause <true|false>             pause/unpause all operations
  grant <id> <role>              grant a role
  revoke <id> <role>             revoke a role
  hold <from> <amount> [benef]   escrow (lock) funds, optional beneficiary
  hold-execute <id> [target]     deliver an active hold
  hold-release <id>              return an active hold
  holds                          list holds
  allowance <id> <amt|unlimited> set a minter's cash-in allowance
  rescue <to> <amount>           recover misdirected treasury funds
  ms-policy                      show the multisig policy (threshold + signers)
  ms-list                        list pending multisig operations
  ms-mint <to> <amount>          propose a multisig mint
  ms-approve <id> <signer_idx>   approve a pending operation
  ms-execute <id>                execute a pending operation at quorum
  attest <reserve> <ref>         record a PQC-signed proof-of-reserve
  oracle <reserve>               set the external reserve-oracle value
  reserve-sync                   sync attested reserve from the oracle
  metadata <value>               set token metadata
  delete                         decommission the token (irreversible)
  account <id>                   show an account balance
  entries                        dump the ledger entry log
`

// buildRequest turns CLI args into an HTTP method, path (relative to base), and
// JSON body. Pure and side-effect free, so it is unit-tested without a server.
func buildRequest(base string, args []string) (method, url string, body []byte, err error) {
	if len(args) == 0 {
		return "", "", nil, fmt.Errorf("no command")
	}
	base = strings.TrimRight(base, "/")
	cmd, rest := args[0], args[1:]

	mustN := func(n int) error {
		if len(rest) != n {
			return fmt.Errorf("%s expects %d argument(s)", cmd, n)
		}
		return nil
	}
	amt := func(s string) (uint64, error) { return strconv.ParseUint(s, 10, 64) }
	enc := func(v any) []byte { b, _ := json.Marshal(v); return b }

	switch cmd {
	case "token":
		return "GET", base + "/token", nil, nil
	case "entries":
		return "GET", base + "/entries", nil, nil
	case "account":
		if err := mustN(1); err != nil {
			return "", "", nil, err
		}
		return "GET", base + "/accounts/" + rest[0], nil, nil
	case "onboard":
		if err := mustN(1); err != nil {
			return "", "", nil, err
		}
		return "POST", base + "/accounts", enc(map[string]string{"id": rest[0]}), nil
	case "kyc":
		if err := mustN(2); err != nil {
			return "", "", nil, err
		}
		verified := rest[1] == "true"
		return "POST", base + "/accounts/" + rest[0] + "/kyc",
			enc(map[string]bool{"verified": verified}), nil
	case "mint":
		if err := mustN(2); err != nil {
			return "", "", nil, err
		}
		a, e := amt(rest[1])
		if e != nil {
			return "", "", nil, e
		}
		return "POST", base + "/mint", enc(map[string]any{"to": rest[0], "amount": a}), nil
	case "transfer":
		if err := mustN(3); err != nil {
			return "", "", nil, err
		}
		a, e := amt(rest[2])
		if e != nil {
			return "", "", nil, e
		}
		return "POST", base + "/transfer",
			enc(map[string]any{"from": rest[0], "to": rest[1], "amount": a}), nil
	case "redeem":
		if err := mustN(2); err != nil {
			return "", "", nil, err
		}
		a, e := amt(rest[1])
		if e != nil {
			return "", "", nil, e
		}
		return "POST", base + "/redeem", enc(map[string]any{"from": rest[0], "amount": a}), nil
	case "burn":
		if err := mustN(2); err != nil {
			return "", "", nil, err
		}
		a, e := amt(rest[1])
		if e != nil {
			return "", "", nil, e
		}
		return "POST", base + "/burn", enc(map[string]any{"from": rest[0], "amount": a}), nil
	case "pause":
		if err := mustN(1); err != nil {
			return "", "", nil, err
		}
		return "POST", base + "/pause", enc(map[string]bool{"paused": rest[0] == "true"}), nil
	case "grant", "revoke":
		if err := mustN(2); err != nil {
			return "", "", nil, err
		}
		return "POST", base + "/accounts/" + rest[0] + "/roles/" + cmd,
			enc(map[string]string{"role": rest[1]}), nil
	case "hold":
		if len(rest) != 2 && len(rest) != 3 {
			return "", "", nil, fmt.Errorf("hold expects <from> <amount> [beneficiary]")
		}
		a, e := amt(rest[1])
		if e != nil {
			return "", "", nil, e
		}
		body := map[string]any{"from": rest[0], "amount": a}
		if len(rest) == 3 {
			body["beneficiary"] = rest[2]
		}
		return "POST", base + "/holds", enc(body), nil
	case "hold-execute":
		if len(rest) != 1 && len(rest) != 2 {
			return "", "", nil, fmt.Errorf("hold-execute expects <id> [target]")
		}
		body := map[string]any{}
		if len(rest) == 2 {
			body["target"] = rest[1]
		}
		return "POST", base + "/holds/" + rest[0] + "/execute", enc(body), nil
	case "hold-release":
		if err := mustN(1); err != nil {
			return "", "", nil, err
		}
		return "POST", base + "/holds/" + rest[0] + "/release", enc(map[string]any{}), nil
	case "holds":
		return "GET", base + "/holds", nil, nil
	case "oracle":
		if err := mustN(1); err != nil {
			return "", "", nil, err
		}
		a, e := amt(rest[0])
		if e != nil {
			return "", "", nil, e
		}
		return "POST", base + "/reserve/oracle", enc(map[string]any{"reserve": a}), nil
	case "reserve-sync":
		return "POST", base + "/reserve/sync", enc(map[string]any{}), nil
	case "metadata":
		if err := mustN(1); err != nil {
			return "", "", nil, err
		}
		return "POST", base + "/token/metadata", enc(map[string]string{"metadata": rest[0]}), nil
	case "delete":
		return "POST", base + "/token/delete", enc(map[string]any{}), nil
	case "allowance":
		if err := mustN(2); err != nil {
			return "", "", nil, err
		}
		if rest[1] == "unlimited" {
			return "POST", base + "/accounts/" + rest[0] + "/allowance",
				enc(map[string]any{"unlimited": true}), nil
		}
		a, e := amt(rest[1])
		if e != nil {
			return "", "", nil, e
		}
		return "POST", base + "/accounts/" + rest[0] + "/allowance",
			enc(map[string]any{"amount": a}), nil
	case "rescue":
		if err := mustN(2); err != nil {
			return "", "", nil, err
		}
		a, e := amt(rest[1])
		if e != nil {
			return "", "", nil, e
		}
		return "POST", base + "/rescue", enc(map[string]any{"to": rest[0], "amount": a}), nil
	case "ms-policy":
		return "GET", base + "/multisig/policy", nil, nil
	case "ms-list":
		return "GET", base + "/multisig", nil, nil
	case "ms-mint":
		if err := mustN(2); err != nil {
			return "", "", nil, err
		}
		a, e := amt(rest[1])
		if e != nil {
			return "", "", nil, e
		}
		return "POST", base + "/multisig",
			enc(map[string]any{"mint": map[string]any{"to": rest[0], "amount": a}}), nil
	case "ms-approve":
		if err := mustN(2); err != nil {
			return "", "", nil, err
		}
		idx, e := strconv.Atoi(rest[1])
		if e != nil {
			return "", "", nil, e
		}
		return "POST", base + "/multisig/" + rest[0] + "/approve",
			enc(map[string]any{"signer_index": idx}), nil
	case "ms-execute":
		if err := mustN(1); err != nil {
			return "", "", nil, err
		}
		return "POST", base + "/multisig/" + rest[0] + "/execute", enc(map[string]any{}), nil
	case "attest":
		if err := mustN(2); err != nil {
			return "", "", nil, err
		}
		a, e := amt(rest[0])
		if e != nil {
			return "", "", nil, e
		}
		return "POST", base + "/attest",
			enc(map[string]any{"reserve": a, "custodian_ref": rest[1]}), nil
	default:
		return "", "", nil, fmt.Errorf("unknown command %q", cmd)
	}
}

func run(base string, args []string, out io.Writer, insecure bool) error {
	method, url, body, err := buildRequest(base, args)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := http.DefaultClient
	if insecure {
		client = &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	fmt.Fprintf(out, "%s\n%s\n", resp.Status, string(respBody))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("request failed: %s", resp.Status)
	}
	return nil
}

func main() {
	base := "https://127.0.0.1:8443"
	insecure := false
	args := os.Args[1:]
	parsing := true
	for parsing && len(args) > 0 {
		switch args[0] {
		case "-url":
			if len(args) < 2 {
				fmt.Fprintln(os.Stderr, "-url needs a value")
				os.Exit(1)
			}
			base, args = args[1], args[2:]
		case "-insecure", "-k":
			insecure, args = true, args[1:]
		default:
			parsing = false
		}
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(usage)
		return
	}
	if err := run(base, args, os.Stdout, insecure); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
