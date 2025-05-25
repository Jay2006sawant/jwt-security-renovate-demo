package main

import (
    "fmt"
    "github.com/dgrijalva/jwt-go"
    "github.com/gin-gonic/gin"
    "net/http"
    "time"
)

// Vulnerable secret key - this is intentionally weak for demonstration
const secretKey = "weak-secret-key"

func main() {
    router := gin.Default()

    // Health check endpoint
    router.GET("/health", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{
            "status": "healthy",
            "time":   time.Now().Format(time.RFC3339),
        })
    })

    // Vulnerable endpoint - demonstrates JWT authentication bypass
    router.GET("/secure-data", func(c *gin.Context) {
        tokenString := c.GetHeader("Authorization")
        if tokenString == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
            return
        }

        // Vulnerable code - doesn't properly validate the token
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            // Vulnerable: Using a weak secret key and not checking signing method
            return []byte(secretKey), nil
        })

        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
            return
        }

        // Vulnerable: Not checking token validity properly
        if claims, ok := token.Claims.(jwt.MapClaims); ok {
            c.JSON(http.StatusOK, gin.H{
                "message": "Access granted to secure data",
                "user":    claims["user"],
                "data":    "This is sensitive data that should be protected",
            })
        } else {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
        }
    })

    // Endpoint to generate a token (for demonstration)
    router.GET("/generate-token", func(c *gin.Context) {
        token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
            "user": "testuser",
            "exp":  time.Now().Add(time.Hour * 24).Unix(),
        })

        // Fix: Use SignedString instead of SigningString to get the complete token with signature
        tokenString, err := token.SignedString([]byte(secretKey))
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
            return
        }

        c.JSON(http.StatusOK, gin.H{"token": tokenString})
    })

    fmt.Println("Server running on http://localhost:8080")
    if err := router.Run(":8080"); err != nil {
        fmt.Printf("Failed to start server: %v\n", err)
    }
} 