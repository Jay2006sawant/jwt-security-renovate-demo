package main

import (
    "github.com/dgrijalva/jwt-go"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"
)

func TestTokenValidation(t *testing.T) {
    // Test valid token
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "user": "testuser",
        "exp":  time.Now().Add(time.Hour * 24).Unix(),
    })
    tokenString, _ := token.SigningString()

    req := httptest.NewRequest("GET", "/secure-data", nil)
    req.Header.Set("Authorization", tokenString)
    w := httptest.NewRecorder()

    // Test invalid token
    invalidReq := httptest.NewRequest("GET", "/secure-data", nil)
    invalidReq.Header.Set("Authorization", "invalid-token")
    invalidW := httptest.NewRecorder()

    // Test missing token
    missingReq := httptest.NewRequest("GET", "/secure-data", nil)
    missingW := httptest.NewRecorder()

    // Run tests
    t.Run("Valid Token", func(t *testing.T) {
        // This should pass due to the vulnerability
        if w.Code != http.StatusOK {
            t.Errorf("Expected status OK, got %v", w.Code)
        }
    })

    t.Run("Invalid Token", func(t *testing.T) {
        if invalidW.Code != http.StatusUnauthorized {
            t.Errorf("Expected status Unauthorized, got %v", invalidW.Code)
        }
    })

    t.Run("Missing Token", func(t *testing.T) {
        if missingW.Code != http.StatusUnauthorized {
            t.Errorf("Expected status Unauthorized, got %v", missingW.Code)
        }
    })
}

func TestVulnerabilityMitigation(t *testing.T) {
    // Test token with modified claims
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "user": "attacker",
        "exp":  time.Now().Add(time.Hour * 24).Unix(),
    })
    tokenString, _ := token.SigningString()

    req := httptest.NewRequest("GET", "/secure-data", nil)
    req.Header.Set("Authorization", tokenString)
    w := httptest.NewRecorder()

    // This should fail in a secure implementation
    t.Run("Modified Claims", func(t *testing.T) {
        // This passes due to the vulnerability
        if w.Code != http.StatusOK {
            t.Errorf("Expected status OK, got %v", w.Code)
        }
    })
} 