package main

import (
	"encoding/json"
	"testing"
)

func TestBuildRequestMint(t *testing.T) {
	m, url, body, err := buildRequest("http://host:8080/", []string{"mint", "acme", "400000"})
	if err != nil {
		t.Fatal(err)
	}
	if m != "POST" || url != "http://host:8080/mint" {
		t.Fatalf("got %s %s", m, url)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["to"] != "acme" || got["amount"].(float64) != 400000 {
		t.Fatalf("bad body: %s", body)
	}
}

func TestBuildRequestToken(t *testing.T) {
	m, url, body, err := buildRequest("http://host:8080", []string{"token"})
	if err != nil {
		t.Fatal(err)
	}
	if m != "GET" || url != "http://host:8080/token" || body != nil {
		t.Fatalf("got %s %s body=%v", m, url, body)
	}
}

func TestBuildRequestArityError(t *testing.T) {
	if _, _, _, err := buildRequest("http://h", []string{"mint", "acme"}); err == nil {
		t.Fatal("expected arity error")
	}
	if _, _, _, err := buildRequest("http://h", []string{"bogus"}); err == nil {
		t.Fatal("expected unknown command error")
	}
}

func TestBuildRequestHoldWithBeneficiary(t *testing.T) {
	m, url, body, err := buildRequest("http://h", []string{"hold", "acme", "300000", "globex"})
	if err != nil {
		t.Fatal(err)
	}
	if m != "POST" || url != "http://h/holds" {
		t.Fatalf("got %s %s", m, url)
	}
	var got map[string]any
	json.Unmarshal(body, &got)
	if got["from"] != "acme" || got["beneficiary"] != "globex" || got["amount"].(float64) != 300000 {
		t.Fatalf("bad hold body: %s", body)
	}
}

func TestBuildRequestGrantRole(t *testing.T) {
	m, url, body, err := buildRequest("http://h", []string{"grant", "acme", "minter"})
	if err != nil {
		t.Fatal(err)
	}
	if m != "POST" || url != "http://h/accounts/acme/roles/grant" {
		t.Fatalf("got %s %s", m, url)
	}
	var got map[string]string
	json.Unmarshal(body, &got)
	if got["role"] != "minter" {
		t.Fatalf("bad role body: %s", body)
	}
}

func TestBuildRequestReserveSync(t *testing.T) {
	m, url, _, err := buildRequest("http://h", []string{"reserve-sync"})
	if err != nil {
		t.Fatal(err)
	}
	if m != "POST" || url != "http://h/reserve/sync" {
		t.Fatalf("got %s %s", m, url)
	}
}

func TestBuildRequestMultisigMint(t *testing.T) {
	m, url, body, err := buildRequest("http://h", []string{"ms-mint", "acme", "400000"})
	if err != nil {
		t.Fatal(err)
	}
	if m != "POST" || url != "http://h/multisig" {
		t.Fatalf("got %s %s", m, url)
	}
	var got map[string]map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["mint"]["to"] != "acme" || got["mint"]["amount"].(float64) != 400000 {
		t.Fatalf("bad ms-mint body: %s", body)
	}
}

func TestBuildRequestAllowanceUnlimited(t *testing.T) {
	_, url, body, err := buildRequest("http://h", []string{"allowance", "sup", "unlimited"})
	if err != nil {
		t.Fatal(err)
	}
	if url != "http://h/accounts/sup/allowance" {
		t.Fatalf("got %s", url)
	}
	var got map[string]any
	json.Unmarshal(body, &got)
	if got["unlimited"] != true {
		t.Fatalf("bad allowance body: %s", body)
	}
}

func TestBuildRequestMsApprove(t *testing.T) {
	m, url, body, err := buildRequest("http://h", []string{"ms-approve", "op123", "1"})
	if err != nil {
		t.Fatal(err)
	}
	if m != "POST" || url != "http://h/multisig/op123/approve" {
		t.Fatalf("got %s %s", m, url)
	}
	var got map[string]any
	json.Unmarshal(body, &got)
	if got["signer_index"].(float64) != 1 {
		t.Fatalf("bad approve body: %s", body)
	}
}
