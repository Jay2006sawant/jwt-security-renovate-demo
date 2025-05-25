package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

func setupRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	
	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
		})
	})

	// Token generation endpoint
	router.GET("/generate-token", func(c *gin.Context) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id": "123",
			"role":    "admin",
		})
		tokenString, _ := token.SignedString([]byte(secretKey))
		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	})

	// Secure data endpoint
	router.GET("/secure-data", func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
			return
		}

		tokenString := authHeader[7:] // Remove "Bearer " prefix
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(secretKey), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "This is secure data",
			"user_id": token.Claims.(jwt.MapClaims)["user_id"],
			"role":    token.Claims.(jwt.MapClaims)["role"],
		})
	})

	return router
}

func TestTokenValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	// Test valid token
	t.Run("Valid Token", func(t *testing.T) {
		// Generate a valid token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id": "123",
			"role":    "admin",
		})
		tokenString, _ := token.SignedString([]byte(secretKey))

		// Create request with valid token
		req := httptest.NewRequest("GET", "/secure-data", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %v", w.Code)
		}
	})

	// Test invalid token
	t.Run("Invalid Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/secure-data", nil)
		req.Header.Set("Authorization", "Bearer invalid.token.here")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %v", w.Code)
		}
	})

	// Test missing token
	t.Run("Missing Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/secure-data", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %v", w.Code)
		}
	})
}

func TestVulnerabilityMitigation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := setupRouter()

	// Test token with modified claims
	t.Run("Modified Claims", func(t *testing.T) {
		// Generate a token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id": "123",
			"role":    "user",
		})
		tokenString, _ := token.SignedString([]byte(secretKey))

		// Modify the token (this should fail validation)
		modifiedToken := tokenString[:len(tokenString)-10] + "modified"

		req := httptest.NewRequest("GET", "/secure-data", nil)
		req.Header.Set("Authorization", "Bearer "+modifiedToken)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401 for modified token, got %v", w.Code)
		}
	})
} 