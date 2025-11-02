package broserver

import (
	"net/http"

	bsc "jonnyzzz.com/oauth2-bro/bro-server-common"
)

func (s *server) token(w http.ResponseWriter, r *http.Request) {
	bsc.Token(s, w, r)
}
