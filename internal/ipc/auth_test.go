package ipc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func buildMalformedSPKIDER(pub *rsa.PublicKey) []byte {
	// Deliberately omit leading 0x00 sign pad on modulus even when high bit is 1,
	// reproducing mainland TL-IPC firmware's non-compliant ASN.1 DER encoding.
	modBytes := pub.N.Bytes()
	expBytes := []byte{0x01, 0x00, 0x01} // 65537

	encodeLen := func(n int) []byte {
		if n < 128 {
			return []byte{byte(n)}
		}
		if n < 256 {
			return []byte{0x81, byte(n)}
		}
		return []byte{0x82, byte(n >> 8), byte(n & 0xff)}
	}
	wrapTLV := func(tag byte, content []byte) []byte {
		out := []byte{tag}
		out = append(out, encodeLen(len(content))...)
		out = append(out, content...)
		return out
	}

	rsaSeq := append(wrapTLV(0x02, modBytes), wrapTLV(0x02, expBytes)...)
	rsaSeqTLV := wrapTLV(0x30, rsaSeq)

	// rsaEncryption OID 1.2.840.113549.1.1.1 + NULL
	algID := []byte{0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00}
	bitString := wrapTLV(0x03, append([]byte{0x00}, rsaSeqTLV...))
	return wrapTLV(0x30, append(algID, bitString...))
}

func TestSecurityEncodeDeterministic(t *testing.T) {
	got, err := SecurityEncode("TestPass123!")
	if err != nil {
		t.Fatalf("SecurityEncode failed: %v", err)
	}
	if len(got) != 15 { // max(len("TestPass123!")=12, len("RDpbLfCPsJZ7fiv")=15)
		t.Fatalf("expected length 15, got %d (%q)", len(got), got)
	}
	gotLong, err := SecurityEncode("averylongpasswordthatisover15chars")
	if err != nil {
		t.Fatalf("SecurityEncode long failed: %v", err)
	}
	if len(gotLong) != len("averylongpasswordthatisover15chars") {
		t.Fatalf("expected length %d, got %d", len("averylongpasswordthatisover15chars"), len(gotLong))
	}
}

func TestMalformedCameraRSAPublicKeyAndLoginEncrypt(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	// Ensure top bit is set on a 1024-bit RSA modulus
	if priv.PublicKey.N.Bytes()[0]&0x80 == 0 {
		t.Fatalf("expected generated RSA modulus to have MSB set")
	}

	malformedDER := buildMalformedSPKIDER(&priv.PublicKey)
	b64 := base64.StdEncoding.EncodeToString(malformedDER)
	// Camera URL-escapes +, /, = in challenge JSON
	escaped := strings.NewReplacer("+", "%2b", "/", "%2f", "=", "%3d").Replace(b64)

	parsed, err := ParseCameraRSAPublicKey(escaped)
	if err != nil {
		t.Fatalf("ParseCameraRSAPublicKey failed on malformed DER: %v", err)
	}
	if parsed.N.Cmp(priv.PublicKey.N) != 0 || parsed.E != priv.PublicKey.E {
		t.Fatalf("parsed public key mismatch")
	}

	cipherB64, err := EncryptLoginPassword("MyCameraSecret99", "nonce_abc", url.PathEscape(b64))
	if err != nil {
		t.Fatalf("EncryptLoginPassword failed: %v", err)
	}
	cipherBytes, err := base64.StdEncoding.DecodeString(cipherB64)
	if err != nil {
		t.Fatalf("decode cipher base64: %v", err)
	}
	plain, err := rsa.DecryptPKCS1v15(rand.Reader, priv, cipherBytes)
	if err != nil {
		t.Fatalf("DecryptPKCS1v15 failed: %v", err)
	}
	obf, _ := SecurityEncode("MyCameraSecret99")
	want := obf + ":nonce_abc"
	if string(plain) != want {
		t.Fatalf("decrypted payload = %q, want %q", string(plain), want)
	}
}
