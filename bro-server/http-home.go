package broserver

import (
	_ "embed"
	"fmt"
	"net/http"
)

func (s *server) home(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(200)
	_, _ = w.Write([]byte(
		fmt.Sprint("OAuth2-bro", "\n\nversion: ", s.version, "\n\n", "OAuth2-bro")))
}
