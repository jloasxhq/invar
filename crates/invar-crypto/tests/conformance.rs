//! Cross-language conformance: assert the Rust glue reproduces, byte-for-byte, the
//! recipes in `conformance/vectors.json`. The Go provider asserts the same file, so
//! the ML-DSA signing preimage is provably identical across the polyglot stack.

use invar_crypto::glue;
use serde_json::Value;

fn load_vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&raw).expect("parse vectors.json")
}

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

/// Parse the `"00*32"` salt shorthand: byte `00` repeated 32 times.
fn parse_salt(spec: &str) -> Vec<u8> {
    if let Some((b, n)) = spec.split_once('*') {
        let byte = u8::from_str_radix(b, 16).expect("salt byte");
        let count: usize = n.parse().expect("salt count");
        vec![byte; count]
    } else {
        hx(spec)
    }
}

#[test]
fn fingerprint_sha384_matches_vector() {
    let v = load_vectors();
    let f = &v["fingerprint"];
    let input = hx(f["input_hex"].as_str().unwrap());
    let expect = hx(f["digest_hex"].as_str().unwrap());
    assert_eq!(
        glue::fingerprint(&input),
        expect,
        "SHA-384 fingerprint mismatch"
    );
}

#[test]
fn canonical_json_signing_preimage_matches_vector() {
    let v = load_vectors();
    let sp = &v["signing_preimage"];
    // Construct the object in the SAME key order as the vector (order is the thing
    // under test). serde_json is built with `preserve_order`, so this is stable.
    let obj = serde_json::json!({
        "cmd": "DPAD_UP",
        "args": { "repeat": "2" },
        "box_id": "node01",
        "nonce": "aabbccddeeff00112233445566778899",
        "ts": 1718600000
    });
    let got = glue::canonical_json(&obj).unwrap();
    assert_eq!(
        got,
        sp["preimage_utf8"].as_str().unwrap().as_bytes(),
        "canonical JSON preimage (utf8) mismatch"
    );
    assert_eq!(
        got,
        hx(sp["preimage_hex"].as_str().unwrap()),
        "canonical JSON preimage (hex) mismatch"
    );
}

#[test]
fn hkdf_sha3_session_key_matches_vector() {
    let v = load_vectors();
    let sk = &v["session_key"];
    let ikm = hx(sk["ikm_hex"].as_str().unwrap());
    let salt = parse_salt(sk["salt_hex"].as_str().unwrap());
    let info = sk["info"].as_str().unwrap().as_bytes();
    let len = sk["len"].as_u64().unwrap() as usize;
    let expect = hx(sk["okm_hex"].as_str().unwrap());
    let got = glue::hkdf_sha3_256(&ikm, &salt, info, len).unwrap();
    assert_eq!(got, expect, "HKDF-SHA3-256 OKM mismatch");
}

#[test]
fn aes256gcm_frame_matches_vector() {
    let v = load_vectors();
    let fr = &v["frame"];
    let key = hx(fr["key_hex"].as_str().unwrap());
    let nonce = hx(fr["nonce_hex"].as_str().unwrap());
    let aad = fr["aad_utf8"].as_str().unwrap().as_bytes();
    let pt = fr["plaintext_utf8"].as_str().unwrap().as_bytes();
    let expect = hx(fr["ciphertext_tag_hex"].as_str().unwrap());

    let sealed = glue::aes256gcm_seal(&key, &nonce, aad, pt).unwrap();
    assert_eq!(sealed, expect, "AES-256-GCM framing mismatch");

    // And it round-trips.
    let opened = glue::aes256gcm_open(&key, &nonce, aad, &sealed).unwrap();
    assert_eq!(opened, pt, "AES-256-GCM decrypt-back mismatch");
}
