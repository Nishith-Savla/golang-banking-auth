package domain

import "github.com/Nishith-Savla/golang-banking-auth/errs"

type AuthRepository interface {
	FindBy(username, password string) (*Login, *errs.AppError)
}
