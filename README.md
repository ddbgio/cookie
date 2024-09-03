# cookie
go package for cookie management

Thanks to [A complete guide to working with Cookies in Go](https://www.alexedwards.net/blog/working-with-cookies-in-go) by Alex Edwards.

## examples
Generate a new 32-byte global secret for the server to use in signing, encryption, and decryption. If you run more than one instance of a server, or expect sessions to persist beyond the lifecycle of a server, you may want to utlize a secrets manager for generating, storing, and distributing this key.
```go
cookieSecret, err = cookie.NewCookieSecret()
if err != nil {
  log.Error("failed to generate secret",
    "error", err,
  )
  panic(err)
}
```

Create unique a new secret for the user's session token:
```go
func newSecret(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}
```

```go
clientCookie := http.Cookie{
  Name:     "my-cookie-name,
  Value:    sessionToken,
  Secure:   true,
  HttpOnly: true,
  SameSite: http.SameSiteStrictMode,
  MaxAge:   3600, // 1 hour
}
// encrypt the cookie
err = cookie.WriteEncrypted(w, userID, clientCookie, cookieSecret)
if err != nil {
  log.Error("failed to write cookie",
    "error", err,
  )
  http.Error(w, "failed to write cookie", http.StatusInternalServerError)
  return
}
```
