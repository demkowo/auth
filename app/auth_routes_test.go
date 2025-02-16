package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	handler "github.com/demkowo/auth/handlers"
	"github.com/demkowo/auth/internal/testutil/mocks"
	service "github.com/demkowo/auth/services"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

var (
	mHandler handler.Account = mocks.NewHandlerMock()
	mService service.Account = mocks.NewServiceMock()
)

func TestRoutes(t *testing.T) {
	registered = false

	gin.SetMode(gin.TestMode)
	router := gin.New()

	addAccountRoutes(router, mHandler, mService)

	type req []struct {
		method   string
		url      string
		header   string
		body     interface{}
		status   int
		response string
	}

	tests := req{
		{"POST", "/api/v1/auth/add", "", nil, http.StatusCreated, `{"message": "account added"}`},
		{"POST", "/api/v1/auth/login", "", map[string]string{"email": "test@example.com", "password": "password"}, http.StatusOK, `{"message": "login successful"}`},
		{"POST", "/api/v1/auth/refresh", "Bearer token", nil, http.StatusOK, `{"message": "token refreshed"}`},
		{"GET", "/api/v1/auth/authenticate", "", nil, http.StatusOK, `{"message": "authenticated"}`},
		{"POST", "/api/v1/auth/block", "Bearer token", nil, http.StatusOK, `{"message": "account blocked"}`},
		{"DELETE", "/api/v1/auth/delete/123", "Bearer token", nil, http.StatusOK, `{"message": "account deleted"}`},
		{"GET", "/api/v1/auth/find", "Bearer token", nil, http.StatusOK, `{"message": "account found"}`},
		{"POST", "/api/v1/auth/get-by-email", "Bearer token", map[string]string{"email": "test@example.com"}, http.StatusOK, `{"message": "account retrieved by email"}`},
		{"GET", "/api/v1/auth/get/123", "Bearer token", nil, http.StatusOK, `{"message": "account retrieved by ID"}`},
		{"POST", "/api/v1/auth/unblock", "Bearer token", nil, http.StatusOK, `{"message": "account unblocked"}`},
		{"PUT", "/api/v1/auth/edit/password", "Bearer token", map[string]string{"new_password": "securepass"}, http.StatusOK, `{"message": "password updated"}`},
		{"POST", "/api/v1/auth/api-key/123", "Bearer token", nil, http.StatusOK, `{"message": "API key added"}`},
		{"DELETE", "/api/v1/auth/delete/api-key", "Bearer token", nil, http.StatusOK, `{"message": "API key deleted"}`},
		{"POST", "/api/v1/auth/roles/add/123", "Bearer token", nil, http.StatusOK, `{"message": "role added"}`},
		{"DELETE", "/api/v1/auth/roles/delete/123", "Bearer token", nil, http.StatusOK, `{"message": "role deleted"}`},
		{"DELETE", "/api/v1/auth/roles/delete", "Bearer token", nil, http.StatusOK, `{"message": "role deleted"}`},
		{"GET", "/api/v1/auth/find/roles/123", "Bearer token", nil, http.StatusOK, `{"message": "roles found"}`},
		{"POST", "/api/v1/auth/edit-roles", "Bearer token", nil, http.StatusOK, `{"message": "roles updated"}`},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.url, func(t *testing.T) {
			var req *http.Request
			var err error

			if tt.body != nil {
				jsonBody, _ := json.Marshal(tt.body)
				req, err = http.NewRequest(tt.method, tt.url, bytes.NewBuffer(jsonBody))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req, err = http.NewRequest(tt.method, tt.url, nil)
			}

			if err != nil {
				t.Fatal(err)
			}

			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if !assert.Equal(t, tt.status, w.Code) {
			}
			if !assert.JSONEq(t, tt.response, w.Body.String()) {
			}
		})
	}

	if assert.Equal(t, true, registered) {
		assert.NotPanics(t, func() {
			addAccountRoutes(router, mHandler, mService)
		})
	}
}
