package main

import "net/http"

func login(w http.ResponseWriter, _ *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(200)
}

//example login http://localhost:8085/realms/toolbox/protocol/openid-connect/auth?response_type=code&access_type=offline&prompt=consent&client_id=tbe-server&scope=profile%20email&redirect_uri=http://localhost:8443/api/login/authenticated&state=uEL3Pxld4xtPnnpsueH1NplZf1wwbkO1lhA3NiCGuDKi-RmzDJiiAMkxmQFxk-bRnXWJeqqrZD_i4ulZ3UJo-g
