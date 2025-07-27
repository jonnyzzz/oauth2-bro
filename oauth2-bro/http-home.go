package main

import (
	_ "embed"
	"fmt"
	"net/http"
)

//go:embed oauth2-bro-favicon.ico
var faviconContent []byte

func home(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(200)
	_, _ = w.Write([]byte(
		fmt.Sprint("OAuth2-bro\n\nversion: ", version, "\n\n", bannerText())))
}

func favicon(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/x-icon")
	w.WriteHeader(200)
	_, _ = w.Write(faviconContent)
}
