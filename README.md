# Vue SSO Implementation with Flask and JWT

A modern Single Sign-On (SSO) implementation using Vue.js frontend applications and Flask backend. This project demonstrates how to build a secure and scalable SSO solution with JWT-based authentication across multiple applications using cookies.

## Features

- 🔐 Secure cookie-based authentication
- 🔄 JWT token management
- ⚡ Fast Vue.js frontend applications
- 🔑 Centralized Flask authentication service
- 🐳 Docker containerization
- 🌐 Cross-domain cookie sharing
- 🚪 Single logout across all applications
- 🕒 Timezone-aware token management (Africa/Kigali)

## Tech Stack

- Frontend: Vue 3 + Vite
- Backend: Flask
- Infrastructure: Docker + Nginx
- Authentication: JWT + Cookie-based sessions

## Project Structure

```
.
├── app1/                      
│   ├── src/
│   │   ├── assets/
│   │   ├── components/
│   │   ├── views/
│   │   │   ├── HomeView.vue
│   │   │   ├── LoginView.vue
│   │   │   └── App.vue
│   │   ├── main.js
│   │   ├── router.js
│   │   └── store.js
│   ├── Dockerfile
│   ├── nginx.conf
│   └── vite.config.js
├── app2/                     
│   └── [Similar structure to app1]
├── auth-service/        
│   ├── app.py
│   ├── Dockerfile
│   └── requirements.txt
├── nginx/                  
│   ├── Dockerfile
│   └── nginx.conf
└── docker-compose.yml
```

## Architecture Overview

The project implements SSO using the following components:

1. **Frontend Apps**: Two separate Vue.js applications running on different domains
2. **Auth Service**: A Flask application handling authentication and JWT management
3. **Nginx**: For serving the Vue apps and handling routing

### How SSO Works in This Implementation

1. User attempts to access App1
2. If not authenticated, redirected to login
3. Upon successful login:
   - JWT token is generated with proper expiration time
   - Token is stored in an HTTP-only cookie
   - Token includes timezone information (CAT/UTC+2)
4. When accessing App2:
   - Cookie is automatically sent to auth service
   - Auth service validates the JWT token
   - If valid, user is automatically logged in

## Custom Domain Setup

### Why Custom Domains?

We use custom domains (.sso.local) for cookie sharing between applications. This is necessary because:

1. Browsers don't allow setting cookies for `localhost` with domain attributes
2. Cross-domain cookie sharing requires a shared parent domain
3. SSO requires cookies to be accessible across different subdomains

### Setting Up Custom Domains

Add the following entries to your `/etc/hosts` file:

```bash
127.0.0.1 sso.local app1.sso.local app2.sso.local
```

## Token Management

JWT tokens are used for authentication with the following characteristics:

1. **Token Creation**: When a user logs in:
   - Token includes username and expiration time
   - Token is timezone-aware (Africa/Kigali)
   - Default expiration time is 10 minutes

2. **Token Validation**: Each request to protected routes verifies:
   - Token signature is valid
   - Token hasn't expired
   - Token timezone information matches server

3. **Token Invalidation**: On logout:
   - Cookie is cleared
   - Client-side state is reset
   - User is redirected to login

## Running the Project

### Prerequisites

- Docker and Docker Compose
- Node.js (for local development)
- Python 3.8+
- Modern web browser
- Root access (for editing /etc/hosts)

### Environment Setup

1. Add domain entries to /etc/hosts:
```bash
sudo echo "127.0.0.1 sso.local app1.sso.local app2.sso.local" >> /etc/hosts
```

2. Clone the repository:
```bash
git clone <repository-url>
cd sso-implementation
```

### Building and Running

1. Build the images:
```bash
docker-compose build
```

2. Start the services:
```bash
docker-compose up -d
```

3. Access the applications:
- App1: http://app1.sso.local:8080
- App2: http://app2.sso.local:8081
- Auth Service: http://sso.local:5001

## Technical Details

### Cookie Configuration

The auth service sets cookies with specific attributes:
```python
response.set_cookie(
    'access_token',
    token,
    httponly=True,
    samesite='Lax',
    secure=False,  # Set to True in production
    max_age=600,  # 10 minutes
    domain='.sso.local',
    path='/'
)
```

### Security Considerations

1. **CORS Configuration**:
   - Strict origin checking
   - Credentials allowed
   - Specific headers exposed

2. **Cookie Security**:
   - HttpOnly flag enabled
   - SameSite policy enforced
   - Domain restriction

3. **Token Security**:
   - Short-lived tokens (10 minutes)
   - Timezone-aware validation
   - Secure token generation

## Production Considerations

For production deployment:

1. Enable HTTPS:
   - Update cookie settings (secure=True)
   - Configure SSL in Nginx
   - Update CORS settings

2. Token Security:
   - Use strong secret keys
   - Consider implementing refresh tokens
   - Adjust token lifetime based on requirements

3. Domain Configuration:
   - Use real domain names
   - Configure proper SSL certificates
   - Update CORS settings

## Troubleshooting

Common issues and solutions:

1. **Cookie Not Set**:
   - Verify domain configuration in /etc/hosts
   - Check browser cookie settings
   - Ensure CORS headers are correct

2. **Authentication Failed**:
   - Check token expiration
   - Verify timezone settings
   - Check cookie domain settings

3. **Cross-Origin Issues**:
   - Verify CORS configuration
   - Check allowed origins
   - Ensure credentials are enabled

4. **Token Expiration Issues**:
   - Verify server and client timezone settings
   - Check token expiration time configuration
   - Monitor clock synchronization between services