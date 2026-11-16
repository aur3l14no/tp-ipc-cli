package ipc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	tpSecurityKey      = "RDpbLfCPsJZ7fiv"
	tpSecurityAlphabet = "yLwVl0zKqws7LgKPRQ84Mdt708T1qQ3Ha7xv3H7NyU84p21BriUWBU43odz3iP4rBL3cD02KZciXTysVXiV8ngg6vL48rPJyAUw0HurW20xqxv9aYb4M9wK1Ae0wlro510qXeU07kV57fQMc8L6aLgMLwygtc0F10a0Dg70TOoouyFhdysuRMO51yY5ZlOZZLEal1h0t9YQW0Ko7oBwmCAHoic4HYbUyVeU3sfQ1xtXcPcf1aT303wAQhv66qzW"
)

// SecurityEncode applies the TP-Link web UI password obfuscation transform
// (UTF-16 code units XOR "RDpbLfCPsJZ7fiv" mapped over the 255-byte dictionary).
func SecurityEncode(password string) (string, error) {
	if !utf8.ValidString(password) {
		return "", errors.New("password is not valid UTF-8")
	}
	u16 := utf16.Encode([]rune(password))
	n := len(u16)
	if len(tpSecurityKey) > n {
		n = len(tpSecurityKey)
	}
	var out strings.Builder
	out.Grow(n)
	for i := 0; i < n; i++ {
		left := 187
		if i < len(u16) {
			left = int(u16[i])
		}
		right := 187
		if i < len(tpSecurityKey) {
			right = int(tpSecurityKey[i])
		}
		idx := (left ^ right) % len(tpSecurityAlphabet)
		out.WriteByte(tpSecurityAlphabet[idx])
	}
	return out.String(), nil
}

type derElement struct {
	tag          byte
	contentStart int
	contentEnd   int
	next         int
}

func readDERElement(buf []byte, offset int) (derElement, error) {
	if offset+2 > len(buf) {
		return derElement{}, errors.New("truncated DER header")
	}
	tag := buf[offset]
	length := int(buf[offset+1])
	contentStart := offset + 2
	if length&0x80 != 0 {
		byteCount := length & 0x7f
		if byteCount == 0 || byteCount > 4 || contentStart+byteCount > len(buf) {
			return derElement{}, errors.New("invalid DER length")
		}
		length = 0
		for i := 0; i < byteCount; i++ {
			length = (length << 8) | int(buf[contentStart+i])
		}
		contentStart += byteCount
	}
	contentEnd := contentStart + length
	if contentEnd > len(buf) {
		return derElement{}, errors.New("truncated DER content")
	}
	return derElement{
		tag:          tag,
		contentStart: contentStart,
		contentEnd:   contentEnd,
		next:         contentEnd,
	}, nil
}

func unsignedDERInteger(buf []byte, el derElement) (*big.Int, error) {
	if el.tag != 0x02 {
		return nil, fmt.Errorf("expected DER INTEGER (0x02), got 0x%02x", el.tag)
	}
	if el.contentStart >= el.contentEnd {
		return nil, errors.New("empty DER INTEGER")
	}
	start := el.contentStart
	for start+1 < el.contentEnd && buf[start] == 0x00 {
		start++
	}
	return new(big.Int).SetBytes(buf[start:el.contentEnd]), nil
}

// ParseCameraRSAPublicKey parses TP-Link camera RSA challenge keys.
// Mainland TL-IPC firmware emits DER INTEGERs without a leading 0x00 sign pad
// when the top modulus bit is 1, which standard x509.ParsePKIXPublicKey rejects.
func ParseCameraRSAPublicKey(encodedKey string) (*rsa.PublicKey, error) {
	unescaped, err := url.PathUnescape(strings.TrimSpace(encodedKey))
	if err != nil {
		return nil, fmt.Errorf("unescape RSA key: %w", err)
	}
	cleaned := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, unescaped)
	der, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("decode base64 RSA key: %w", err)
	}

	outer, err := readDERElement(der, 0)
	if err != nil || outer.tag != 0x30 {
		return nil, errors.New("RSA key is not a DER SEQUENCE")
	}

	first, err := readDERElement(der, outer.contentStart)
	if err != nil {
		return nil, fmt.Errorf("read RSA outer sequence: %w", err)
	}

	rsaSeq := outer
	if first.tag == 0x30 {
		bitString, err := readDERElement(der, first.next)
		if err != nil || bitString.tag != 0x03 || bitString.contentStart >= bitString.contentEnd || der[bitString.contentStart] != 0x00 {
			return nil, errors.New("invalid SubjectPublicKeyInfo BIT STRING")
		}
		rsaSeq, err = readDERElement(der, bitString.contentStart+1)
		if err != nil || rsaSeq.tag != 0x30 {
			return nil, errors.New("invalid inner RSAPublicKey SEQUENCE")
		}
	}

	modEl, err := readDERElement(der, rsaSeq.contentStart)
	if err != nil {
		return nil, fmt.Errorf("read RSA modulus: %w", err)
	}
	expEl, err := readDERElement(der, modEl.next)
	if err != nil {
		return nil, fmt.Errorf("read RSA exponent: %w", err)
	}

	modulus, err := unsignedDERInteger(der, modEl)
	if err != nil {
		return nil, fmt.Errorf("invalid RSA modulus: %w", err)
	}
	exponent, err := unsignedDERInteger(der, expEl)
	if err != nil {
		return nil, fmt.Errorf("invalid RSA exponent: %w", err)
	}
	if modulus.BitLen() < 512 || !exponent.IsInt64() || exponent.Int64() < 3 {
		return nil, errors.New("RSA public key parameters out of range")
	}

	return &rsa.PublicKey{
		N: modulus,
		E: int(exponent.Int64()),
	}, nil
}

// EncryptLoginPassword encodes and RSA-PKCS1v15 encrypts "<securityEncode(pw)>:<nonce>".
func EncryptLoginPassword(password, nonce, encodedKey string) (string, error) {
	pub, err := ParseCameraRSAPublicKey(encodedKey)
	if err != nil {
		return "", err
	}
	obfuscated, err := SecurityEncode(password)
	if err != nil {
		return "", err
	}
	plaintext := []byte(obfuscated + ":" + nonce)
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, plaintext)
	if err != nil {
		return "", fmt.Errorf("RSA PKCS#1 v1.5 encrypt failed: %w", err)
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
