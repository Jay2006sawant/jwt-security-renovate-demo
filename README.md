# JWT Security Renovate Demo

This project demonstrates a critical security vulnerability (CVE-2020-26160) in the `github.com/dgrijalva/jwt-go` package and how Renovate helps manage such vulnerabilities.

## Project Setup

### Prerequisites
- Go 1.21 or later
- Git

### Installation

1. Clone the repository:
```bash
git clone https://github.com/Jay2006sawant/jwt-security-renovate-demo.git
cd jwt-security-renovate-demo
```

2. Install dependencies:
```bash
go mod download
```

3. Run the server:
```bash
go run main.go
```

### Testing the Server

The server includes a health check endpoint:
```bash
curl http://localhost:8080/health
```

Expected response:
```json
{
    "status": "healthy",
    "time": "2024-03-14T12:00:00Z"
}
```

## Next Steps

In the upcoming commits, we will:
1. Implement the vulnerable JWT authentication
2. Add token generation endpoint
3. Configure Renovate for security updates
4. Add comprehensive documentation about the vulnerability 