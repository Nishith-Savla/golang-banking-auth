package domain

import "github.com/Nishith-Savla/golang-banking-lib/errs"

type AuthRepository interface {
	FindBy(username, password string) (*Login, *errs.AppError)
	GenerateAndStoreRefreshTokenToStore(token AuthToken) (string, *errs.AppError)
}
