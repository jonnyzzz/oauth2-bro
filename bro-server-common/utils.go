package bro_server_common

import (
	"log"
	"net/http"
)

type Handler http.HandlerFunc

func WrapResponseFactory(version string) func(handler Handler) Handler {
	return func(handler Handler) Handler {
		return func(writer http.ResponseWriter, request *http.Request) {
			log.Println("request", request.URL.Path)
			writer.Header().Set("Expires", "11 Aug 1984 14:21:33 GMT")
			writer.Header().Set("X-oauth2-bro-version", version)
			handler(writer, request)
		}
	}
}

// BadRequest sends a bad request response
func BadRequest(w http.ResponseWriter, _ *http.Request, message string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte("Bad Request. \n\n" + message))
}
