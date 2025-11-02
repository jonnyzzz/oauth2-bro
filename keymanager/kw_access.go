package keymanager

import (
	gojwt "github.com/golang-jwt/jwt/v5"
	"jonnyzzz.com/oauth2-bro/user"
)

type BroAccessKeys interface {
	Jwks() ([]byte, error)
	ToBroKeys() BroKeys
	RenderJwtAccessToken(userInfo *user.UserInfo) (string, error)
	ExpirationSeconds() int
}

type broAccessKeysImpl struct {
	Keys BroKeys
}

func NewTokenKeysFrom(Keys BroKeys) BroAccessKeys {
	return &broAccessKeysImpl{
		Keys: Keys,
	}
}

func (tk *broAccessKeysImpl) ToBroKeys() BroKeys {
	return tk.Keys
}

func (tk *broAccessKeysImpl) Jwks() ([]byte, error) {
	return tk.Keys.Jwks()
}

func (tk *broAccessKeysImpl) RenderJwtAccessToken(userInfo *user.UserInfo) (string, error) {
	claims := gojwt.MapClaims{
		"sid":  userInfo.Sid,
		"sub":  userInfo.Sub,
		"name": userInfo.UserName,
	}

	if len(userInfo.UserEmail) > 0 {
		claims["email"] = userInfo.UserEmail
	}

	return tk.Keys.RenderJwtToken(claims)
}

func (tk *broAccessKeysImpl) ExpirationSeconds() int {
	return tk.Keys.ExpirationSeconds()
}
