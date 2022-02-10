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

func (t AuthToken) newRefreshToken() (string, *errs.AppError) {
	c := t.token.Claims.(Claims)
	refreshClaims := c.RefreshTokenClaims()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	signedString, err := token.SignedString([]byte(HmacSampleSecret))
	if err != nil {
		logger.Error("Failed while signing refresh token: " + err.Error())
		return "", errs.NewUnexpectedError("couldn't generate refresh token")
	}
	return signedString, nil
}

func NewAuthToken(claims Claims) AuthToken {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return AuthToken{token}
}
