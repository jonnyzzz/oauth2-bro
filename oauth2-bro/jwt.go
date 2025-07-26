package main

import gojwt "github.com/golang-jwt/jwt/v5"

var SigningMethodRSA *gojwt.SigningMethodRSA

func init_jwt() {
	SigningMethodRSA = gojwt.SigningMethodRS512
}
