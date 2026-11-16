package ipc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aur3l14no/tp-ipc-cli/internal/config"
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

func TestMD5LoginHandshakeAndTimeoutRelogin(t *testing.T) {
	gotHash, err := MD5LoginPassword("TestPass123!", "5sBC6X76")
	if err != nil {
		t.Fatalf("MD5LoginPassword failed: %v", err)
	}
	// Verified against camera web-static/lib/jsencrypt.js $.md5("TestPass123!:5sBC6X76")
	const wantHash = "4e10e0099fd9e8edca39958e7d9c1f48"
	if gotHash != wantHash {
		t.Fatalf("MD5LoginPassword = %q, want %q", gotHash, wantHash)
	}

	var dsCalls atomic.Int32
	var logins atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/pc/Content.htm":
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error_code": -40401,
				"data": map[string]any{
					"code":             -40407,
					"encrypt_type":     []string{"1", "2"},
					"key":              "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgOEf9cqvy0Zt1Ebwv65kxgVEGIRA8Gljs%2fSPbTgVvsWTP6RrphMn6IZHD0T46U0qR8MQYLKeMjo7VKRy5Rb5ZlHu1povGUcYZ1FqLpLu1SecFipiFLxkuAGmLZnS42WA4UzvQFPkUCS3rpvFiK7YcXABunjuXT8w%2bI7zxOI89pX5AgMBAAE%3d",
					"nonce":            "5sBC6X76",
					"md5_encrypt_type": 1,
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/":
			var req struct {
				Method string `json:"method"`
				Login  struct {
					Username       string `json:"username"`
					Password       string `json:"password"`
					EncryptType    string `json:"encrypt_type"`
					MD5EncryptType string `json:"md5_encrypt_type"`
				} `json:"login"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode login request: %v", err)
			}
			if req.Login.Username == "locked" {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error_code": -40401,
					"data": map[string]any{
						"code":     -40404,
						"sec_left": 120,
					},
				})
				return
			}
			if req.Method != "do" || req.Login.Username != "admin" || req.Login.Password != wantHash || req.Login.EncryptType != "2" || req.Login.MD5EncryptType != "1" {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error_code": -40401,
					"data":       map[string]any{"code": -40401},
				})
				return
			}
			n := logins.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error_code": 0,
				"stok":       "md5stok_" + string(rune('0'+n)),
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/ds"):
			if dsCalls.Add(1) == 1 {
				// Simulate ESESSIONTIMEOUT (-40403) on first call to verify auto-relogin
				_ = json.NewEncoder(w).Encode(map[string]any{"error_code": -40403})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error_code": 0,
				"device_info": map[string]any{
					"basic_info": map[string]any{"device_model": "TL-IPC44AW"},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	scheme, host, port, err := config.ParseHostInput(srv.URL)
	if err != nil {
		t.Fatalf("ParseHostInput: %v", err)
	}
	client, err := NewClient(config.Settings{
		Scheme:   scheme,
		Host:     host,
		HTTPPort: port,
		User:     "admin",
		Password: "TestPass123!",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	info, err := client.DeviceInfo(context.Background())
	if err != nil {
		t.Fatalf("DeviceInfo over md5_encrypt_type=1 failed: %v", err)
	}
	if info.Model != "TL-IPC44AW" {
		t.Fatalf("DeviceInfo.Model = %q, want TL-IPC44AW", info.Model)
	}
	if logins.Load() != 2 {
		t.Fatalf("expected 2 logins (initial + relogin after -40403), got %d", logins.Load())
	}

	// Verify lockout surfaces remaining seconds
	lockedClient, _ := NewClient(config.Settings{
		Scheme:   scheme,
		Host:     host,
		HTTPPort: port,
		User:     "locked",
		Password: "TestPass123!",
	})
	_, err = lockedClient.DeviceInfo(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != ErrCodeLocked || !strings.Contains(err.Error(), "120s remaining") {
		t.Fatalf("expected lockout APIError with remaining seconds, got %v", err)
	}
}
