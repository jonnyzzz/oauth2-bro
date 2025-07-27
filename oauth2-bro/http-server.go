package main

import (
	"log"
	"net/http"
)

func init() {
	http.HandleFunc("/", wrapResponse(home))
	http.HandleFunc("/favicon.ico", wrapResponse(favicon))
	http.HandleFunc("/health", wrapResponse(health))
	http.HandleFunc("/jwks", wrapResponse(jwks))
	http.HandleFunc("/login", wrapResponse(login))
	http.HandleFunc("/token", wrapResponse(token))
}

func wrapResponse(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		log.Println("request", request.URL.Path)
		writer.Header().Set("Expires", "11 Aug 1984 11:21:33 GMT")
		writer.Header().Set("X-oauth2-bro-version", version)
		handler(writer, request)
	}
}
