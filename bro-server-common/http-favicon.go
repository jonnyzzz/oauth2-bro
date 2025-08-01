package bro_server_common

import (
	_ "embed"
	"net/http"
)

//go:embed oauth2-bro-favicon.ico
var faviconContent []byte

func FaviconHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/x-icon")
	w.WriteHeader(200)
	_, _ = w.Write(faviconContent)
}
