package cryptobox

import (
	"crypto/fips140"
	"crypto/mlkem"
)

// FIPSEnabled reports whether the Go Cryptographic Module is operating in
// FIPS 140-3 mode (GODEBUG=fips140=on|only). Under CMVP certificate #5247 this is
// the validated software boundary used before an HSM assumes key custody.
func FIPSEnabled() bool {
	return fips140.Enabled()
}

// MLKEMSharedSecret runs a full ML-KEM-768 (NIST FIPS 203) key establishment and
// returns the shared secrets held by each side. In a healthy implementation they
// are equal; this demonstrates the PQC KEM used for hybrid transport keys.
func MLKEMSharedSecret() (encapSecret, decapSecret []byte, err error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, err
	}
	ek := dk.EncapsulationKey()
	sharedEncap, ciphertext := ek.Encapsulate()
	sharedDecap, err := dk.Decapsulate(ciphertext)
	if err != nil {
		return nil, nil, err
	}
	return sharedEncap, sharedDecap, nil
}
