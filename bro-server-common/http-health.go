package bro_server_common

import "net/http"

func HealthHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(200)
	_, _ = w.Write([]byte("Alive\n\n"))
}
