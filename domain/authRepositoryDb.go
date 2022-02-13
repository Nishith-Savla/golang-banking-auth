package domain

import (
	"database/sql"
	"github.com/Nishith-Savla/golang-banking-lib/errs"
	"github.com/Nishith-Savla/golang-banking-lib/logger"
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
			return nil, errs.NewAuthenticationError("invalid credentials")
		}
		logger.Error("Error while verifying login request from database: " + err.Error())
		return nil, errs.NewUnexpectedError("unexpected database error")
	}

	return &login, nil
}

func (d AuthRepositoryDb) GenerateAndStoreRefreshTokenToStore(authToken AuthToken) (string, *errs.AppError) {
	// generate the refresh token
	var refreshToken string
	var appError *errs.AppError

	if refreshToken, appError = authToken.newRefreshToken(); appError != nil {
		return "", appError
	}

	// store it to the store
	sqlInsert := "INSERT INTO refresh_token_store (refresh_token) VALUES (?)"
	_, err := d.client.Exec(sqlInsert, refreshToken)
	if err != nil {
		logger.Error("Error while storing refresh token to database: " + err.Error())
		return "", errs.NewUnexpectedError("unexpected database error")
	}

	return refreshToken, nil
}

func (d AuthRepositoryDb) RefreshTokenExists(refreshToken string) *errs.AppError {
	sqlSelect := "SELECT refresh_token FROM refresh_token_store WHERE refresh_token = ?"
	var token string
	err := d.client.Get(&token, sqlSelect, refreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return errs.NewAuthenticationError("refresh token not registered in the store")
		}
		logger.Error("Error while retrieving refresh token from the database: " + err.Error())
		return errs.NewUnexpectedError("unexpected database error")
	}
	return nil
}

func NewAuthRepositoryDb(dbClient *sqlx.DB) AuthRepositoryDb {
	return AuthRepositoryDb{dbClient}
}
