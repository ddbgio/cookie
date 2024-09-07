# cookie
![badge](https://github.com/ddbgio/cookie/actions/workflows/test.yml/badge.svg)

go package for cookie management

Thanks to [A complete guide to working with Cookies in Go](https://www.alexedwards.net/blog/working-with-cookies-in-go) by Alex Edwards.

> [!WARNING]
> Versions 1 and 2 should have been 0.1 and 0.2, respectively. Version history may be altered or rewritten to reset the current implementation as 1.0.0. [^butwhytho]

[^butwhytho]: I was experimenting downstream with package management.

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
	// use crypto/rand, not math/rand, for values
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}
```

After a user authenticates via another means, establish a session by storing an ecrypted cookie in the format `id:token`.
```go
// generate a user's new session token (length of 32 required)
sessionToken, err := newSecret(32)

// make a cookie using that secret
clientCookie := http.Cookie{
  Name:     "my-cookie-name",
  Value:    sessionToken,
  Secure:   true,
  HttpOnly: true,
  SameSite: http.SameSiteStrictMode,
  MaxAge:   3600, // 1 hour
}

// encrypt the cookie
err = cookie.WriteEncrypted(w, userID, clientCookie, cookieSecret)
if err != nil {
  log.Error("failed to write cookie", "error", err)
  http.Error(w, "failed to write cookie", http.StatusInternalServerError)
  return
}
```

The user will now send the encrypted token back with every request until expiry. That id/token combination can be stored in the backend on creation, and checked on all subsequent requests. Ensure existence and parity of expiration dates for all cookies.
