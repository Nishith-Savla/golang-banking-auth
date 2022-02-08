package service

import (
	"errors"
	"github.com/Nishith-Savla/golang-banking-auth/domain"
	"github.com/Nishith-Savla/golang-banking-auth/dto"
	"github.com/Nishith-Savla/golang-banking-auth/errs"
	"github.com/Nishith-Savla/golang-banking-auth/logger"
	"github.com/golang-jwt/jwt"
)

type AuthService interface {
	Login(req dto.LoginRequest) (*string, *errs.AppError)
	Verify(urlParams map[string]string) (bool, error)
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

func (s DefaultAuthService) Verify(urlParams map[string]string) (bool, error) {

	// convert the string token to JWT struct
	jwtToken, err := jwtTokenFromString(urlParams["token"])
	if err != nil {
		return false, err
	}

	if !jwtToken.Valid {
		return false, errors.New("invalid token")
	}

	// type cast the token claims to jwt.MapClaims
	mapClaims := jwtToken.Claims.(jwt.MapClaims)

	// converting the map claims to JWT struct
	claims, err := domain.BuildClaimsFromJwtMapClaims(mapClaims)
	if err != nil {
		return false, err
	}

	if claims.IsUser() {
		if !claims.IsRequestVerifiedWithTokenClaims(urlParams) {
			return false, nil
		}
	}
	isAuthorized := s.rolePermissions.IsAuthorizedFor(claims.Role, urlParams["routeName"])
	return isAuthorized, nil
}

func jwtTokenFromString(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.HmacSampleSecret), nil
	})

	if err != nil {
		logger.Error("Error while parsing token: " + err.Error())
		return nil, err
	}

	return token, nil
}

func NewAuthService(repo domain.AuthRepository) DefaultAuthService {
	return DefaultAuthService{repo, domain.GetRolePermissions()}
}
