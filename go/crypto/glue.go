// Package cryptobox provides the Go side of stablecoin-forge's cryptography:
// the deterministic "glue" (canonical JSON, SHA-384, HKDF-SHA3, AES-256-GCM) that
// must agree byte-for-byte with the Rust provider, plus ML-KEM key establishment
// and a FIPS-mode check. Everything here is Go standard library only, so the
// module builds with no third-party dependencies.
package cryptobox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/json"
	"fmt"
)

// CanonicalJSON encodes v as canonical JSON: compact separators, struct field
// order preserved, HTML escaping disabled (to match Python/Rust output). This is
// the exact byte string that gets signed.
func CanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Fingerprint returns the SHA-384 (FIPS 180-4) digest of data.
func Fingerprint(data []byte) []byte {
	sum := sha512.Sum384(data)
	return sum[:]
}

// HKDFSHA3_256 derives keyLength bytes via HKDF (RFC 5869) with SHA3-256
// (FIPS 202). An empty salt means the RFC's all-zero salt of hash length.
func HKDFSHA3_256(ikm, salt []byte, info string, keyLength int) ([]byte, error) {
	return hkdf.Key(sha3.New256, ikm, salt, info, keyLength)
}

// AES256GCMSeal encrypts plaintext with AES-256-GCM (NIST SP 800-38D). The nonce
// must be 12 bytes; the 16-byte tag is appended to the ciphertext.
func AES256GCMSeal(key, nonce, aad, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 key must be 32 bytes, got %d", len(key))
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("GCM nonce must be 12 bytes, got %d", len(nonce))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

// AES256GCMOpen is the inverse of AES256GCMSeal.
func AES256GCMOpen(key, nonce, aad, ctTag []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ctTag, aad)
}
