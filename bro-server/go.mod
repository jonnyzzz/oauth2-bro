module jonnyzzz.com/oauth2-bro/bro-server

go 1.24.5

require (
	github.com/golang-jwt/jwt/v5 v5.3.0
	github.com/rakutentech/jwk-go v1.2.0
	jonnyzzz.com/oauth2-bro/bro-server-common v0.0.0
	jonnyzzz.com/oauth2-bro/client v0.0.0
	jonnyzzz.com/oauth2-bro/keymanager v0.0.0
	jonnyzzz.com/oauth2-bro/user v0.0.0
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
)

replace (
	jonnyzzz.com/oauth2-bro/bro-server-common => ../bro-server-common
	jonnyzzz.com/oauth2-bro/client => ../client
	jonnyzzz.com/oauth2-bro/keymanager => ../keymanager
	jonnyzzz.com/oauth2-bro/user => ../user
)
