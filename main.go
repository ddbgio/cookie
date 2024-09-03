// package cookie implements basic, signed, and ecrypted cookies,
// drawing heavily from Alex Edward's work on cookies in Go:
// https://www.alexedwards.net/blog/working-with-cookies-in-go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const secretLength = 32

var (
	ErrInitiation    = errors.New("initialization failure")
	ErrEncryption    = errors.New("encryption failure")
	ErrCookie        = errors.New("cookie failure")
	ErrSecretMissing = errors.New("secret key is missing")
)

// NewCookieSecret generates a random secret key for use with signed or encrypted cookies.
// Assumes secretLength is 32.
func NewCookieSecret() ([]byte, error) {
	length := secretLength
	secret := make([]byte, length)
	_, err := rand.Read(secret)
	if err != nil {
		return nil, fmt.Errorf("unable to generate random secret: %w", err)
	}
	return secret, nil
}

// Write a cookie to the response without any additional modifications
// and basic length validation
func Write(w http.ResponseWriter, cookie http.Cookie) error {
	// only a small subset of US ASCII is supported, so we base64 encode
	cookie.Value = base64.URLEncoding.EncodeToString([]byte(cookie.Value))

	// not all browsers will prohibit long cookies, so we set a conservative limit
	if len(cookie.String()) > 4096 {
		return fmt.Errorf("%w: cookie value too long", ErrCookie)
	}

	http.SetCookie(w, &cookie)
	return nil
}

// Read a basic base64 encoded cookie from the request, returning the decoded string
func Read(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", fmt.Errorf("'%s' not found: %w", name, err)
	}
	value, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", fmt.Errorf("cannot decode (%s=%v): %w", name, cookie.Value, err)
	}
	return string(value), nil
}

// WriteSigned writes a cookie to the response with a sha256 HMAC signature.
// A signed cookie can be read by the client, but is tamper-evident.
func WriteSigned(w http.ResponseWriter, cookie http.Cookie, secretKey []byte) error {
	if len(secretKey) == 0 {
		return ErrSecretMissing
	}
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(cookie.Name))
	mac.Write([]byte(cookie.Value))
	signature := mac.Sum(nil)
	cookie.Value = fmt.Sprintf("%s%s", string(signature), cookie.Value) // TODO is this missing a colon?
	return Write(w, cookie)
}

// ReadSigned reads a cookie from the request and verifies the sha256 HMAC signature
// A signed cookie can be read by the client, but is tamper-evident.
func ReadSigned(r *http.Request, name string, secretKey []byte) (string, error) {
	if len(secretKey) == 0 {
		return "", ErrSecretMissing
	}
	signedValue, err := Read(r, name)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrCookie, err)
	}
	if len(signedValue) < sha256.Size {
		return "", fmt.Errorf("%w: %w", ErrCookie, errors.New("signature wrong length"))
	}
	signature := signedValue[:sha256.Size]
	value := signedValue[sha256.Size:]
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(name))
	mac.Write([]byte(value))
	expectedSignature := mac.Sum(nil)

	if !hmac.Equal([]byte(signature), expectedSignature) {
		return "", fmt.Errorf("%w: %w", ErrCookie, errors.New("signature mismatch"))
	}
	return value, nil
}

// WriteEcrypted writes a cookie to the response with an AES-GCM encrypted value
// An encrypted cookie cannot be read by the client.
func WriteEncrypted(w http.ResponseWriter, cookie http.Cookie, secretKey []byte) error {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return fmt.Errorf("unable to create new cypher block for write: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("unable to create new GCM for write: %w", err)
	}
	nonce := make([]byte, aesGCM.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return fmt.Errorf("unable to read random bytes into nonce: %w", err)
	}
	plaintext := fmt.Sprintf("%s:%s", cookie.Name, cookie.Value)
	encryptedValue := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	cookie.Value = string(encryptedValue)
	return Write(w, cookie)
}

// ReadEncrypted reads a cookie from the request and decrypts the AES-GCM encrypted value
// An encrypted cookie cannot be read by the client.
func ReadEncrypted(r *http.Request, name string, secretKey []byte) (string, error) {
	encryptedValue, err := Read(r, name)
	if err != nil {
		return "", fmt.Errorf("unable to read encrypted cookie: %w", err)
	}
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", fmt.Errorf("unable to create new cypher block for read: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("unable to create new GCM for read: %w", err)
	}
	nonceSize := aesGCM.NonceSize()
	if len(encryptedValue) < nonceSize {
		err := errors.New("encrypted value too short")
		return "", fmt.Errorf("%w: %w", ErrCookie, err)
	}
	nonce := encryptedValue[:nonceSize]
	ciphertext := encryptedValue[nonceSize:]
	plaintext, err := aesGCM.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		return "", fmt.Errorf("unable to decrypt cookie: %w", err)
	}
	expectedName, value, ok := strings.Cut(string(plaintext), ":")
	if !ok {
		err := errors.New("unable to split plaintext")
		return "", fmt.Errorf("%w: %w", ErrCookie, err)
	}
	if expectedName != name {
		details := fmt.Errorf("expected '%s' but got '%s'", name, expectedName)
		err := fmt.Errorf("name mismatch: %w", details)
		return "", fmt.Errorf("%w: %w", ErrCookie, err)
	}
	return value, nil
}
