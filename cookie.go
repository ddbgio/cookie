package main

import (
	"net/http"
	"time"
)

// Cookie defines an HTTP cookie. For more information see:
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
type Cookie struct {
	Name   string
	Value  string
	Path   string // defaults to creation path
	Domain string // deafults to creation host

	Expires    time.Time
	RawExpires string

	// MaxAge=0 means no 'Max-Age' attribute specified.
	// MaxAge<0 means delete cookie now, equivalently 'Max-Age: 0'
	// MaxAge>0 means Max-Age attribute present and given in seconds
	MaxAge   int
	Secure   bool // only send via HTTPS or localhost
	HttpOnly bool // when true, JavaScript cannot access

	// SameSite allows a server to define a cookie attribute making it impossible for the browser to send this cookie along with cross-site requests.
	SameSite http.SameSite

	Raw      string
	Unparsed []string
}
