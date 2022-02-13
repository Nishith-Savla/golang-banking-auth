package domain

import (
	"github.com/golang-jwt/jwt"
	"time"
)

const HmacSampleSecret = "HMAC_SAMPLE_SECRET"
const AccessTokenDuration = time.Hour
const RefreshTokenDuration = time.Hour * 24 * 30

type AccessTokenClaims struct {
	CustomerId string   `json:"customer_id"`
	Accounts   []string `json:"accounts"`
	Username   string   `json:"username"`
	Role       string   `json:"role"`
	//Expiry     int64    `json:"exp"`
	jwt.StandardClaims
}

type RefreshTokenClaims struct {
	TokenType  string   `json:"token_type"`
	CustomerId string   `json:"customer_id"`
	Accounts   []string `json:"accounts"`
	Username   string   `json:"username"`
	Role       string   `json:"role"`
	//Expiry     int64    `json:"exp"`
	jwt.StandardClaims
}

func (c AccessTokenClaims) IsUser() bool {
	return c.Role == "user"
}

func (c AccessTokenClaims) IsValidCustomerId(customerId string) bool {
	return c.CustomerId == customerId
}

func (c AccessTokenClaims) IsValidAccountId(accountId string) bool {
	if accountId == "" {
		return true
	}
	for _, a := range c.Accounts {
		if a == accountId {
			return true
		}
	}
	return false
}

func (c AccessTokenClaims) IsRequestVerifiedWithTokenClaims(urlParams map[string]string) bool {
	if c.IsValidCustomerId(urlParams["customer_id"]) && c.IsValidAccountId(urlParams["account_id"]) {
		return true
	}
	return false
}

func (c AccessTokenClaims) RefreshTokenClaims() RefreshTokenClaims {
	return RefreshTokenClaims{
		TokenType:  "refresh_token",
		CustomerId: c.CustomerId,
		Accounts:   c.Accounts,
		Username:   c.Username,
		Role:       c.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(RefreshTokenDuration).Unix(),
		},
	}
}

func (c RefreshTokenClaims) AccessTokenClaims() AccessTokenClaims {
	return AccessTokenClaims{
		CustomerId: c.CustomerId,
		Accounts:   c.Accounts,
		Username:   c.Username,
		Role:       c.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(AccessTokenDuration).Unix(),
		},
	}
}
