# JWT Security Renovate Demo

This project demonstrates a critical security vulnerability (CVE-2020-26160) in the `github.com/dgrijalva/jwt-go` package and how Renovate helps manage such vulnerabilities.

## Critical Vulnerability: CVE-2020-26160

This vulnerability allows attackers to bypass authentication by manipulating JWT tokens. The issue is in the token validation process where the package doesn't properly verify the token's signature.

### Impact
- Authentication bypass
- Unauthorized access to protected resources
- Potential data breach
- Security compromise

### Affected Versions
- All versions of github.com/dgrijalva/jwt-go before v4.0.0

## Project Setup

### Prerequisites
- Go 1.21 or later
- Git

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/jwt-security-renovate-demo.git
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

1. Health Check:
```bash
curl http://localhost:8080/health
```

2. Generate a Token:
```bash
curl http://localhost:8080/generate-token
```

3. Access Secure Data:
```bash
curl -H "Authorization: <token>" http://localhost:8080/secure-data
```

### Demonstrating the Vulnerability

The server implements a vulnerable JWT authentication system that can be bypassed. The vulnerability exists because:
1. Weak secret key is used
2. Token validation is not properly implemented
3. Signing method is not verified
4. Token claims are not properly validated

## Renovate Configuration

This project uses Renovate to automatically update dependencies when security vulnerabilities are detected. The configuration in `renovate.json` includes:

### Security Updates
- Automatically creates PRs for security vulnerabilities
- Runs vulnerability checks at any time
- Labels PRs with "security" and "critical"
- Includes detailed commit messages with vulnerability information

### Update Rules
- Automatically merges minor and patch updates
- Disables major version updates
- Uses semantic versioning
- Includes detailed PR descriptions

### Example Renovate PR
When Renovate detects the JWT vulnerability, it will:
1. Create a PR to update to a secure version
2. Label it as a security update
3. Include details about the vulnerability
4. Provide instructions for testing the fix

## Next Steps

In the upcoming commits, we will:
1. Add comprehensive documentation about the vulnerability
2. Demonstrate how to fix the vulnerability
3. Add security best practices 