package main

import (
    "fmt"
    "github.com/dgrijalva/jwt-go"
    "github.com/gin-gonic/gin"
    "net/http"
    "time"
)

func main() {
    // Initialize the Gin router
    router := gin.Default()

    // Basic health check endpoint
    router.GET("/health", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{
            "status": "healthy",
            "time":   time.Now().Format(time.RFC3339),
        })
    })

    // Start the server
    fmt.Println("Server running on http://localhost:8080")
    if err := router.Run(":8080"); err != nil {
        fmt.Printf("Failed to start server: %v\n", err)
    }
} 