package cryptobox

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

type vectors struct {
	SessionKey struct {
		IKMHex  string `json:"ikm_hex"`
		Info    string `json:"info"`
		SaltHex string `json:"salt_hex"`
		Len     int    `json:"len"`
		OKMHex  string `json:"okm_hex"`
	} `json:"session_key"`
	Frame struct {
		KeyHex           string `json:"key_hex"`
		NonceHex         string `json:"nonce_hex"`
		AADUTF8          string `json:"aad_utf8"`
		PlaintextUTF8    string `json:"plaintext_utf8"`
		CiphertextTagHex string `json:"ciphertext_tag_hex"`
	} `json:"frame"`
	Fingerprint struct {
		InputHex  string `json:"input_hex"`
		DigestHex string `json:"digest_hex"`
	} `json:"fingerprint"`
	SigningPreimage struct {
		PreimageUTF8 string `json:"preimage_utf8"`
		PreimageHex  string `json:"preimage_hex"`
	} `json:"signing_preimage"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("../../conformance/vectors.json")
	if err != nil {
		t.Fatalf("read vectors.json: %v", err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors.json: %v", err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

// parseSalt expands the "00*32" shorthand (byte 00 repeated 32 times).
func parseSalt(t *testing.T, spec string) []byte {
	t.Helper()
	if i := strings.IndexByte(spec, '*'); i >= 0 {
		b := mustHex(t, spec[:i])
		n, err := strconv.Atoi(spec[i+1:])
		if err != nil {
			t.Fatalf("salt count: %v", err)
		}
		return bytes.Repeat(b, n)
	}
	return mustHex(t, spec)
}

func TestFingerprintSHA384(t *testing.T) {
	v := loadVectors(t)
	got := Fingerprint(mustHex(t, v.Fingerprint.InputHex))
	if !bytes.Equal(got, mustHex(t, v.Fingerprint.DigestHex)) {
		t.Fatalf("SHA-384 fingerprint mismatch")
	}
}

// preimage models the signing object in the SAME field order as the vector, which
// is the property under test (canonical JSON preserves order).
type preimage struct {
	Cmd   string            `json:"cmd"`
	Args  map[string]string `json:"args"`
	BoxID string            `json:"box_id"`
	Nonce string            `json:"nonce"`
	Ts    int64             `json:"ts"`
}

func TestCanonicalJSONSigningPreimage(t *testing.T) {
	v := loadVectors(t)
	obj := preimage{
		Cmd:   "DPAD_UP",
		Args:  map[string]string{"repeat": "2"},
		BoxID: "node01",
		Nonce: "aabbccddeeff00112233445566778899",
		Ts:    1718600000,
	}
	got, err := CanonicalJSON(obj)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != v.SigningPreimage.PreimageUTF8 {
		t.Fatalf("canonical JSON mismatch:\n got=%s\nwant=%s", got, v.SigningPreimage.PreimageUTF8)
	}
	if !bytes.Equal(got, mustHex(t, v.SigningPreimage.PreimageHex)) {
		t.Fatalf("canonical JSON hex mismatch")
	}
}

func TestHKDFSHA3SessionKey(t *testing.T) {
	v := loadVectors(t)
	got, err := HKDFSHA3_256(
		mustHex(t, v.SessionKey.IKMHex),
		parseSalt(t, v.SessionKey.SaltHex),
		v.SessionKey.Info,
		v.SessionKey.Len,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, mustHex(t, v.SessionKey.OKMHex)) {
		t.Fatalf("HKDF-SHA3-256 OKM mismatch")
	}
}

func TestAES256GCMFrame(t *testing.T) {
	v := loadVectors(t)
	key := mustHex(t, v.Frame.KeyHex)
	nonce := mustHex(t, v.Frame.NonceHex)
	aad := []byte(v.Frame.AADUTF8)
	pt := []byte(v.Frame.PlaintextUTF8)

	sealed, err := AES256GCMSeal(key, nonce, aad, pt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sealed, mustHex(t, v.Frame.CiphertextTagHex)) {
		t.Fatalf("AES-256-GCM framing mismatch")
	}
	opened, err := AES256GCMOpen(key, nonce, aad, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, pt) {
		t.Fatalf("AES-256-GCM decrypt-back mismatch")
	}
}

func TestMLKEM768SharedSecret(t *testing.T) {
	a, b, err := MLKEMSharedSecret()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("ML-KEM-768 shared secrets differ")
	}
	if len(a) != 32 {
		t.Fatalf("ML-KEM-768 shared secret len = %d, want 32", len(a))
	}
}

func TestFIPSModeObservable(t *testing.T) {
	// Just exercise the boundary check; value depends on GODEBUG=fips140.
	t.Logf("FIPS 140-3 mode enabled: %v", FIPSEnabled())
}
