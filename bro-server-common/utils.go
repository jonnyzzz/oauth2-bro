package bro_server_common

import (
	"log"
	"net/http"
)

func WrapResponseFactory(version string) func(handler http.HandlerFunc) http.HandlerFunc {
	return func(handler http.HandlerFunc) http.HandlerFunc {
		return func(writer http.ResponseWriter, request *http.Request) {
			WrapResponse(writer, request, version)
			handler(writer, request)
		}
	}
}

func WrapResponse(writer http.ResponseWriter, request *http.Request, version string) {
	log.Println("request", request.URL.Path)
	WrapResponseHeaders(writer.Header(), version)
}

func WrapResponseHeaders(header http.Header, version string) {
	header.Set("Expires", "11 Aug 1984 14:21:33 GMT")
	header.Set("X-oauth2-bro-version", version)
}

func BadRequest(w http.ResponseWriter, _ *http.Request, message string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte("Bad Request. \n\n" + message))
}
