package domain

import (
	"github.com/golang-jwt/jwt"
)

const HmacSampleSecret = "HMAC_SAMPLE_SECRET"

type Claims struct {
	CustomerId string   `json:"customer_id"`
	Accounts   []string `json:"accounts"`
	Username   string   `json:"username"`
	Role       string   `json:"role"`
	//Expiry     int64    `json:"exp"`
	jwt.StandardClaims
}

func (c Claims) IsUser() bool {
	return c.Role == "user"
}

func (c Claims) IsValidCustomerId(customerId string) bool {
	return c.CustomerId == customerId
}

func (c Claims) IsValidAccountId(accountId string) bool {
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

func (c Claims) IsRequestVerifiedWithTokenClaims(urlParams map[string]string) bool {
	if c.IsValidCustomerId(urlParams["customer_id"]) && c.IsValidAccountId(urlParams["account_id"]) {
		return true
	}
	return false
}
