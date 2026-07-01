// Package dlt is the distributed-ledger adapter for stablecoin-forge. It mirrors
// the Rust LedgerPort so the same domain flows can target a permissioned chain
// (e.g. Hyperledger Fabric) instead of the custodial ledger.
//
// This is an intentional stub: the methods return ErrNotImplemented. It documents
// the integration seam so a Fabric backend can be dropped in without touching the
// domain layer.
//
// Fabric mapping (see docs/FIPS-PQC.md and docs/ROADMAP.md):
//   - Identities/keys  -> Fabric MSP, enrolled via the CA. Phase 0 uses the SW
//     BCCSP; Phase 1 flips BCCSP to PKCS#11 so keys live in an HSM (re-enroll, not
//     import). Build Fabric with Go FIPS mode (GODEBUG=fips140=on).
//   - Token operations -> chaincode functions (mint/burn/transfer/redeem/...),
//     with the totalSupply <= reserve invariant enforced in-chaincode.
//   - Proof-of-reserve -> ML-DSA-65-signed attestation anchored on-ledger.
package dlt

import "errors"

// ErrNotImplemented is returned by every method of the stub adapter.
var ErrNotImplemented = errors.New("dlt: Fabric adapter not implemented (stub)")

// Account mirrors the domain account shape carried across the port.
type Account struct {
	ID      string
	Balance uint64
	Frozen  bool
}

// LedgerPort is the Go-side counterpart of forge-core's LedgerPort trait.
type LedgerPort interface {
	IsRegistered(id string) (bool, error)
	Register(id string) error
	Account(id string) (Account, error)
	SetAccount(a Account) error
	TotalSupply() (uint64, error)
	SetTotalSupply(v uint64) error
	AttestedReserve() (uint64, error)
	SetAttestedReserve(v uint64) error
}

// FabricAdapter is a placeholder implementation targeting Hyperledger Fabric.
type FabricAdapter struct {
	// ChannelID, ChaincodeName, MSPID, gateway connection, etc. go here.
	ChannelID     string
	ChaincodeName string
}

// NewFabricAdapter constructs a (non-functional) Fabric adapter stub.
func NewFabricAdapter(channelID, chaincodeName string) *FabricAdapter {
	return &FabricAdapter{ChannelID: channelID, ChaincodeName: chaincodeName}
}

func (*FabricAdapter) IsRegistered(string) (bool, error)     { return false, ErrNotImplemented }
func (*FabricAdapter) Register(string) error                 { return ErrNotImplemented }
func (*FabricAdapter) Account(string) (Account, error)       { return Account{}, ErrNotImplemented }
func (*FabricAdapter) SetAccount(Account) error              { return ErrNotImplemented }
func (*FabricAdapter) TotalSupply() (uint64, error)          { return 0, ErrNotImplemented }
func (*FabricAdapter) SetTotalSupply(uint64) error           { return ErrNotImplemented }
func (*FabricAdapter) AttestedReserve() (uint64, error)      { return 0, ErrNotImplemented }
func (*FabricAdapter) SetAttestedReserve(uint64) error       { return ErrNotImplemented }

// Compile-time assertion that the stub satisfies the port.
var _ LedgerPort = (*FabricAdapter)(nil)
