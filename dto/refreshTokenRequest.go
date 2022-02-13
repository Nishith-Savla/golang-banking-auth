package dto

import (
	"errors"
	"github.com/Nishith-Savla/golang-banking-auth/domain"
	"github.com/Nishith-Savla/golang-banking-lib/logger"
	"github.com/golang-jwt/jwt"
)

type RefreshTokenRequest struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func (r RefreshTokenRequest) IsAccessTokenValid() *jwt.ValidationError {

	// 1. invalid token
	// 2. valid token but expired
	_, err := jwt.Parse(r.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.HmacSampleSecret), nil
	})
	if err != nil {
		var validationError *jwt.ValidationError
		if errors.As(err, &validationError) {
			return validationError
		}

		logger.Error("Failed while parsing token: " + err.Error())
		return validationError
	}
	return nil
}
