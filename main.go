// TODO give less information to the client when a cookie fails

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
)

var (
	ErrValueTooLong     = errors.New("cookie value too long")
	ErrInvalidValue     = errors.New("invalid cookie value")
	ErrSecretKeyMissing = errors.New("secret key missing")
)

var secretKey []byte

func main() {
	secret, ok := os.LookupEnv("COOKIE_SECRET")
	secretKey = []byte(secret)
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

func setCookieHandler(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Name:     "example_cookie",
		Value:    "oatmeal_raisin",
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	err := Write(w, cookie)
	if err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Cookie set!"))
}

func getCookieHandler(w http.ResponseWriter, r *http.Request) {
	value, err := Read(r, "example_cookie")
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
