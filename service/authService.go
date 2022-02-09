package service

import (
	"fmt"
	"github.com/Nishith-Savla/golang-banking-auth/domain"
	"github.com/Nishith-Savla/golang-banking-auth/dto"
	"github.com/Nishith-Savla/golang-banking-lib/errs"
	"github.com/golang-jwt/jwt"
)

type AuthService interface {
	Login(req dto.LoginRequest) (*string, *errs.AppError)
	Verify(urlParams map[string]string) *errs.AppError
}

type DefaultAuthService struct {
	repo            domain.AuthRepository
	rolePermissions domain.RolePermissions
}

func (s DefaultAuthService) Login(req dto.LoginRequest) (*string, *errs.AppError) {
	login, err := s.repo.FindBy(req.Username, req.Password)
	if err != nil {
		return nil, err
	}
	token, err := login.GenerateToken()
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (s DefaultAuthService) Verify(urlParams map[string]string) *errs.AppError {

	// convert the string token to JWT struct
	jwtToken, err := jwtTokenFromString(urlParams["token"])
	if err != nil {
		return errs.NewAuthorizationError(err.Error())
	}

	if !jwtToken.Valid {
		return errs.NewAuthorizationError("invalid token")
	}

	// type cast the token claims to jwt.MapClaims
	claims := jwtToken.Claims.(*domain.Claims)

	if claims.IsUser() {
		if !claims.IsRequestVerifiedWithTokenClaims(urlParams) {
			return errs.NewAuthorizationError("request not verified with the token claims")
		}
	}

	isAuthorized := s.rolePermissions.IsAuthorizedFor(claims.Role, urlParams["routeName"])
	if isAuthorized {
		return nil
	}

	return errs.NewAuthorizationError(fmt.Sprintf("%s role is not authorized", claims.Role))

}

func jwtTokenFromString(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &domain.Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.HmacSampleSecret), nil
	})
	if err != nil {
		return nil, err
	}

	return token, nil
}

func NewAuthService(repo domain.AuthRepository) DefaultAuthService {
	return DefaultAuthService{repo, domain.GetRolePermissions()}
}
