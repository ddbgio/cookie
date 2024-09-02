package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
)

func main() {
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

func setCookieHandler(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Name:     "example_cookie",
		Value:    "chocolate_chip",
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	// adds a `Set-Cookie` header
	http.SetCookie(w, &cookie)
	w.Write([]byte("Cookie set!"))
}

func getCookieHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("example_cookie")
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			http.Error(w, "cookie not found", http.StatusBadRequest)
		default:
			log.Println(err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}

	fmt.Fprintf(w, "Cookie value is: %s", cookie.Value)
}
