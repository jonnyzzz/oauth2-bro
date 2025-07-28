package main

import (
	"fmt"
	gojwt "github.com/golang-jwt/jwt/v5"
)

type BroInnerKeys interface {
	SignInnerToken(userInfo *UserInfo) (string, error)
	ValidateInnerToken(tokenString string) (*UserInfo, error)
}

type broInnerKeysImpl struct {
	Keys       BroKeys
	broVersion string
}

func NewInnerKeys(Keys BroKeys, broVersion string) BroInnerKeys {
	return &broInnerKeysImpl{
		Keys:       Keys,
		broVersion: broVersion,
	}
}

func (tk *broInnerKeysImpl) SignInnerToken(userInfo *UserInfo) (string, error) {
	claims := gojwt.MapClaims{
		"bro": tk.broVersion,
	}

	for k, v := range userInfo.ToInnerJwtClaims() {
		claims[k] = v
	}

	token, err := tk.Keys.RenderJwtToken(claims)
	return token, err
}

func (tk *broInnerKeysImpl) ValidateInnerToken(tokenString string) (*UserInfo, error) {
	type InnerClaims struct {
		Bro string `json:"bro"`
		gojwt.RegisteredClaims
		UserInfo
	}

	token, err := tk.Keys.ValidateJwtToken(tokenString, &InnerClaims{})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*InnerClaims)
	if !ok {
		return nil, fmt.Errorf("failed to cast claims to InnerClaims")
	}

	if claims.Bro != tk.broVersion {
		return nil, fmt.Errorf("Unsupported code claim version. ")
	}

	userInfo := &claims.UserInfo
	return userInfo, nil
}
