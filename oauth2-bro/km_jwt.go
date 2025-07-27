package main

import gojwt "github.com/golang-jwt/jwt/v5"

// SigningMethod returns the JWT signing method
func (_ *broKeysImpl) SigningMethod() *gojwt.SigningMethodRSA {
	return gojwt.SigningMethodRS512
}
