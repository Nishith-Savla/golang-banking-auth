package domain

import (
	"database/sql"
	"github.com/Nishith-Savla/golang-banking-auth/errs"
	"github.com/Nishith-Savla/golang-banking-auth/logger"
	"github.com/jmoiron/sqlx"
)

type AuthRepositoryDb struct {
	client *sqlx.DB
}

func (d AuthRepositoryDb) FindBy(username, password string) (*Login, *errs.AppError) {
	var login Login
	sqlVerify := `SELECT ANY_VALUE(username) as username, a.customer_id, ANY_VALUE(role) as role, group_concat(a.account_id) as account_numbers FROM users u
                    LEFT JOIN accounts a ON a.customer_id = u.customer_id
                	WHERE username = ? and password = ?
                	GROUP BY a.customer_id`
	if err := d.client.Get(&login, sqlVerify, username, password); err != nil {
		if err == sql.ErrNoRows {
			return nil, errs.NewAuthorizationError("invalid credentials")
		}
		logger.Error("Error while verifying login request from database: " + err.Error())
		return nil, errs.NewUnexpectedError("unexpected database error")
	}

	return &login, nil
}

func NewAuthRepositoryDb(dbClient *sqlx.DB) AuthRepositoryDb {
	return AuthRepositoryDb{dbClient}
}
