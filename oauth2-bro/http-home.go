package main

import (
	"fmt"
	"net/http"
)

func home(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(200)
	_, _ = w.Write([]byte(
		fmt.Sprint("OAuth2-bro\n\nversion: ", version, "\n\n", bannerText())))
}
