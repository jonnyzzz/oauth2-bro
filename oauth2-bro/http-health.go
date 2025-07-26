package main

import "net/http"

func health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(200)
	_, _ = w.Write([]byte("Alive\n\n"))
}
