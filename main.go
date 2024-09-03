// TODO give less information to the client when a cookie fails

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
	"log"
	"net/http"
	"os"
	"strings"
)

var (
	ErrValueTooLong     = errors.New("cookie value too long")
	ErrInvalidValue     = errors.New("invalid cookie value")
	ErrSecretKeyMissing = errors.New("secret key missing")
)

var secretKey []byte

func main() {
	secret, ok := os.LookupEnv("COOKIE_SECRET")
	if len(secret) < 32 {
		log.Fatal("COOKIE_SECRET must be at least 32 characters long")
	}
	secretKey = []byte(secret[:32])
	if !ok {
		log.Fatal("COOKIE_SECRET environment variable not set")
	}

	port := ":8000"
	mux := http.NewServeMux()
	mux.HandleFunc("/set", setCookieHandler)
	mux.HandleFunc("/get", getCookieHandler)
	log.Printf("Listening on http://localhost%v ...", port)
	err := http.ListenAndServe(port, mux)
	if err != nil {
		log.Fatal(err)
	}
}

// Write a basic insecure cookie
func Write(w http.ResponseWriter, cookie http.Cookie) error {
	// only a small subset of US ASCII is supported, so we base64 encode
	cookie.Value = base64.URLEncoding.EncodeToString([]byte(cookie.Value))

	// not all browsers will prohibit long cookies,
	// but we set a conservative limit to be sure
	if len(cookie.String()) > 4096 {
		return ErrValueTooLong
	}

	http.SetCookie(w, &cookie)
	return nil
}

func Read(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", fmt.Errorf("cookie '%s' not found: %w", name, err)
	}
	value, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidValue, err)
	}
	return string(value), nil
}

func WriteSigned(w http.ResponseWriter, cookie http.Cookie, secretKey []byte) error {
	if len(secretKey) == 0 {
		return ErrSecretKeyMissing
	}
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(cookie.Name))
	mac.Write([]byte(cookie.Value))
	signature := mac.Sum(nil)
	cookie.Value = fmt.Sprintf("%s%s", string(signature), cookie.Value)
	return Write(w, cookie)
}

func ReadSigned(r *http.Request, name string, secretKey []byte) (string, error) {
	if len(secretKey) == 0 {
		return "", ErrSecretKeyMissing
	}
	signedValue, err := Read(r, name)
	if err != nil {
		return "", err
	}
	if len(signedValue) < sha256.Size {
		return "", fmt.Errorf("%w: %w", ErrInvalidValue, errors.New("signature wrong length"))
	}
	signature := signedValue[:sha256.Size]
	value := signedValue[sha256.Size:]
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(name))
	mac.Write([]byte(value))
	expectedSignature := mac.Sum(nil)

	if !hmac.Equal([]byte(signature), expectedSignature) {
		return "", fmt.Errorf("%w: %w", ErrInvalidValue, errors.New("signature mismatch"))
	}
	return value, nil
}

func WriteEcrypted(w http.ResponseWriter, cookie http.Cookie, secretKey []byte) error {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return fmt.Errorf("unable to create new cypher block: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("unable to create new GCM: %w", err)
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

func ReadEncrypted(r *http.Request, name string, secretKey []byte) (string, error) {
	encryptedValue, err := Read(r, name)
	if err != nil {
		return "", fmt.Errorf("unable to read cookie: %w", err)
	}
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", fmt.Errorf("unable to create new cypher block: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("unable to create new GCM: %w", err)
	}
	nonceSize := aesGCM.NonceSize()
	if len(encryptedValue) < nonceSize {
		err := errors.New("encrypted value too short")
		return "", fmt.Errorf("%w: %w", ErrInvalidValue, err)
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
		return "", fmt.Errorf("%w: %w", ErrInvalidValue, err)
	}
	if expectedName != name {
		err := errors.New("name mismatch")
		return "", fmt.Errorf("%w: %w", ErrInvalidValue, err)
	}
	return value, nil
}

func setCookieHandler(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Name:     "example_cookie",
		Value:    "chocolate fudge",
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	err := WriteEcrypted(w, cookie, secretKey)
	if err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Cookie set!"))
}

func getCookieHandler(w http.ResponseWriter, r *http.Request) {
	value, err := ReadEncrypted(r, "example_cookie", secretKey)
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			http.Error(w, "cookie not found", http.StatusBadRequest)
		case errors.Is(err, ErrInvalidValue):
			http.Error(w, "invalid cookie value", http.StatusBadRequest)
		default:
			log.Println(err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}
	w.Write([]byte(value))
}
