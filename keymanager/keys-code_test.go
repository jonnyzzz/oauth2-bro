package keymanager

import (
	"testing"

	"jonnyzzz.com/oauth2-bro/user"
)

func TestCodeIsValidOptimistic(t *testing.T) {
	// Create a new keymanager instance for this test
	keyManager := NewKeyManager()

	userInfo := &user.UserInfo{
		Sid:       "sid",
		Sub:       "sub",
		UserName:  "Eugene Petrenko",
		UserEmail: "me@jonnyzzz.com",
	}

	token, err := keyManager.CodeKeys.SignInnerToken(userInfo)
	if err != nil {
		t.Error(err)
		return
	}

	keymanagerUserInfo, err := keyManager.CodeKeys.ValidateInnerToken(token)
	if err != nil {
		t.Error(err)
	}

	if keymanagerUserInfo == nil {
		t.Error("Code token validation failed")
		return
	}

	// Convert keymanager UserInfo to user module UserInfo for comparison
	parsedUser := &user.UserInfo{
		Sid:       keymanagerUserInfo.Sid,
		Sub:       keymanagerUserInfo.Sub,
		UserName:  keymanagerUserInfo.UserName,
		UserEmail: keymanagerUserInfo.UserEmail,
	}

	if parsedUser.String() != userInfo.String() {
		t.Error("Incorrectly restored user info: ", parsedUser.String(), " != ", userInfo.String(), "")
	}

	if *parsedUser != *userInfo {
		t.Error("Incorrectly restored user info.")
	}
}

func TestRandomCode(t *testing.T) {
	// Create a new keymanager instance for this test
	keyManager := NewKeyManager()

	token := "this is broken key"

	ok, err := keyManager.CodeKeys.ValidateInnerToken(token)
	if err == nil || ok != nil {
		t.Error(err)
	}
}

//TODO: include more tests specific to the JWT and expiration
