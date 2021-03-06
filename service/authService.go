package service

import (
	"fmt"
	"github.com/Nishith-Savla/golang-banking-auth/domain"
	"github.com/Nishith-Savla/golang-banking-auth/dto"
	"github.com/Nishith-Savla/golang-banking-lib/errs"
	"github.com/golang-jwt/jwt"
)

type AuthService interface {
	Login(req dto.LoginRequest) (*dto.LoginResponse, *errs.AppError)
	Verify(urlParams map[string]string) *errs.AppError
	Refresh(request dto.RefreshTokenRequest) (*dto.LoginResponse, *errs.AppError)
}

type DefaultAuthService struct {
	repo            domain.AuthRepository
	rolePermissions domain.RolePermissions
}

func (s DefaultAuthService) Login(req dto.LoginRequest) (*dto.LoginResponse, *errs.AppError) {
	var appError *errs.AppError
	var login *domain.Login

	if login, appError = s.repo.FindBy(req.Username, req.Password); appError != nil {
		return nil, appError
	}

	claims := login.ClaimsForAccessToken()
	authToken := domain.NewAuthToken(claims)

	var accessToken, refreshToken string

	if accessToken, appError = authToken.NewAccessToken(); appError != nil {
		return nil, appError
	}
	if refreshToken, appError = s.repo.GenerateAndStoreRefreshTokenToStore(authToken); appError != nil {
		return nil, appError
	}

	return &dto.LoginResponse{AccessToken: accessToken, RefreshToken: refreshToken}, nil
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
	claims := jwtToken.Claims.(*domain.AccessTokenClaims)

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

func (s DefaultAuthService) Refresh(request dto.RefreshTokenRequest) (*dto.LoginResponse, *errs.AppError) {
	var validationError *jwt.ValidationError

	if validationError = request.IsAccessTokenValid(); validationError == nil {
		return nil, errs.NewAuthenticationError("cannot generate new access token until the current one expires")
	}

	if validationError.Errors != jwt.ValidationErrorExpired {
		return nil, errs.NewAuthenticationError("invalid token")
	}

	// continue with the refresh token functionality

	var accessToken string
	var appError *errs.AppError

	if appError = s.repo.RefreshTokenExists(request.RefreshToken); appError != nil {
		return nil, appError
	}

	// generate an access token from refresh token
	if accessToken, appError = domain.NewAccessTokenFromRefreshToken(request.RefreshToken); appError != nil {
		return nil, appError
	}

	return &dto.LoginResponse{AccessToken: accessToken}, nil
}

func jwtTokenFromString(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &domain.AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
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
