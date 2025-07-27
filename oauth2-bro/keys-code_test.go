package main

import (
	"testing"
)

func TestCodeIsValidOptimistic(t *testing.T) {
	init_code_keys()

	token, err := SignCodeToken()
	if err != nil {
		t.Error(err)
		return
	}

	ok, err := ValidateCodeToken(token)
	if err != nil {
		t.Error(err)
	}

	if !ok {
		t.Error("Code token validation failed")
	}
}

func TestRandomCode(t *testing.T) {
	init_code_keys()

	token := "this is broken key"

	ok, err := ValidateCodeToken(token)
	if err == nil || ok {
		t.Error(err)
	}
}

//TODO: include more tests specific to the JWT and expiration
