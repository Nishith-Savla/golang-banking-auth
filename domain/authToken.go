package domain

import (
	"github.com/Nishith-Savla/golang-banking-lib/errs"
	"github.com/Nishith-Savla/golang-banking-lib/logger"
	"github.com/golang-jwt/jwt"
)

type AuthToken struct {
	token *jwt.Token
}

func (t AuthToken) NewAccessToken() (string, *errs.AppError) {
	signedString, err := t.token.SignedString([]byte(HmacSampleSecret))
	if err != nil {
		logger.Error("Failed while signing access token: " + err.Error())
		return "", errs.NewUnexpectedError("couldn't generate access token")
	}

	return signedString, nil
}

func NewAuthToken(claims Claims) AuthToken {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return AuthToken{token}
}
