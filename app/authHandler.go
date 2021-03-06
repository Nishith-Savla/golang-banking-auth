package app

import (
	"encoding/json"
	"fmt"
	"github.com/Nishith-Savla/golang-banking-auth/dto"
	"github.com/Nishith-Savla/golang-banking-auth/service"
	"github.com/Nishith-Savla/golang-banking-lib/logger"
	"net/http"
)

type AuthHandler struct {
	service service.AuthService
}

func (h AuthHandler) NotImplementedHandler(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprint(w, "Handler not implemented...")
}

func (h AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var loginRequest dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		logger.Error("Error while decoding loginRequest: " + err.Error())
		writeJSONResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	token, appError := h.service.Login(loginRequest)
	if appError != nil {
		writeJSONResponse(w, appError.Code, appError.AsMessage())
		return
	}

	writeJSONResponse(w, http.StatusOK, *token)
}

// Sample URL string for Verify
// http://localhost:8001/auth/verify?token=somevalidtokenstring&routeName=GetCustomer&customer_id=2000&account_id=95470

func (h AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var refreshTokenRequest dto.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&refreshTokenRequest); err != nil {
		logger.Error("Error while decoding refreshTokenRequest: " + err.Error())
		writeJSONResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	token, appError := h.service.Refresh(refreshTokenRequest)
	if appError != nil {
		writeJSONResponse(w, appError.Code, appError.AsMessage())
		return
	}

	writeJSONResponse(w, http.StatusOK, *token)
}

func (h AuthHandler) Verify(w http.ResponseWriter, r *http.Request) {
	urlParams := make(map[string]string)
	query := r.URL.Query()
	for k, _ := range query {
		urlParams[k] = query.Get(k)
	}

	if urlParams["token"] == "" {
		writeJSONResponse(w, http.StatusForbidden, unauthorizedResponse("missing token"))
		return
	}

	if appError := h.service.Verify(urlParams); appError != nil {
		writeJSONResponse(w, appError.Code, unauthorizedResponse(appError.Message))
		return
	}

	writeJSONResponse(w, http.StatusOK, authorizedResponse())
}
func authorizedResponse() map[string]bool {
	return map[string]bool{"isAuthorized": true}
}

func unauthorizedResponse(message string) map[string]interface{} {
	return map[string]interface{}{
		"isAuthorized": false,
		"message":      message,
	}
}

func writeJSONResponse(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		logger.Panic(err.Error())
	}
}
