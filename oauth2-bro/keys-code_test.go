package main

import (
	"testing"
)

func TestCodeIsValidOptimistic(t *testing.T) {
	init_code_keys()

	userInfo := &UserInfo{
		Sid:       "sid",
		Sub:       "sub",
		UserName:  "Eugene Petrenko",
		UserEmail: "me@jonnyzzz.com",
	}

	token, err := CodeKeys.SignInnerToken(userInfo)
	if err != nil {
		t.Error(err)
		return
	}

	parsedUser, err := CodeKeys.ValidateInnerToken(token)
	if err != nil {
		t.Error(err)
	}

	if parsedUser == nil {
		t.Error("Code token validation failed")
		return
	}

	if parsedUser.String() != userInfo.String() {
		t.Error("Incorrectly restored user info: ", parsedUser.String(), " != ", userInfo.String(), "")
	}

	if *parsedUser != *userInfo {
		t.Error("Incorrectly restored user info.")
	}
}

func TestRandomCode(t *testing.T) {
	init_code_keys()

	token := "this is broken key"

	ok, err := CodeKeys.ValidateInnerToken(token)
	if err == nil || ok != nil {
		t.Error(err)
	}
}

//TODO: include more tests specific to the JWT and expiration
