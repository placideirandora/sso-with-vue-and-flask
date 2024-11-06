# Vue SSO Implementation with Flask and Redis

A modern Single Sign-On (SSO) implementation using Vue.js frontend applications and Flask/Redis backend. This project demonstrates how to build a secure and scalable SSO solution with session management across multiple applications using cookies and Redis.

## Features

- 🔐 Secure cookie-based authentication
- 🔄 Shared session management with Redis
- ⚡ Fast Vue.js frontend applications
- 🔑 Centralized Flask authentication service
- 🐳 Docker containerization
- 🌐 Cross-domain cookie sharing
- 📝 JWT token implementation
- 🚪 Single logout across all applications

## Tech Stack

- Frontend: Vue 3 + Vite
- Backend: Flask + Redis
- Infrastructure: Docker + Nginx
- Authentication: JWT + Cookie-based sessions

## Project Structure

```
.
├── app1/                      
│   ├── node_modules/
│   ├── src/
│   │   ├── assets/
│   │   │   └── main.css
│   │   ├── components/
│   │   │   └── NavBar.vue
│   │   ├── views/
│   │   │   ├── HomeView.vue
│   │   │   ├── LoginView.vue
│   │   │   └── App.vue
│   │   ├── main.js
│   │   ├── router.js
│   │   └── store.js
│   ├── .gitignore
│   ├── Dockerfile
│   ├── index.html
│   ├── nginx.conf
│   ├── package-lock.json
│   ├── package.json
│   └── vite.config.js
├── app2/                     
│   ├── node_modules/
│   ├── src/
│   │   ├── assets/
│   │   │   └── main.css
│   │   ├── components/
│   │   │   └── NavBar.vue
│   │   ├── views/
│   │   │   ├── HomeView.vue
│   │   │   ├── LoginView.vue
│   │   │   └── App.vue
│   │   ├── main.js
│   │   ├── router.js
│   │   └── store.js
│   ├── .gitignore
│   ├── Dockerfile
│   ├── index.html
│   ├── nginx.conf
│   ├── package-lock.json
│   ├── package.json
│   └── vite.config.js
├── auth-service/        
│   ├── app.py
│   ├── Dockerfile
│   └── requirements.txt
├── nginx/                  
│   ├── Dockerfile
│   └── nginx.conf
├── docker-compose.yml
└── README.md
```

## Architecture Overview

The project implements SSO using the following components:

1. **Frontend Apps**: Two separate Vue.js applications running on different domains
2. **Auth Service**: A Flask application handling authentication and session management
3. **Redis**: For storing session information
4. **Nginx**: For serving the Vue apps and handling routing

### How SSO Works in This Implementation

1. User attempts to access App1
2. If not authenticated, redirected to login
3. Upon successful login:
   - JWT token is generated
   - Session is stored in Redis
   - Cookie is set with the JWT token
4. When accessing App2:
   - Cookie is automatically sent to auth service
   - Auth service validates token with Redis
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

## Session Management with Redis

Redis is used for session storage and management:

1. **Session Creation**: When a user logs in, their session info is stored in Redis with:
   - Key: `session:{token}`
   - Value: Serialized user data
   - Expiry: 1 hour (configurable)

2. **Session Validation**: Each request to protected routes verifies:
   - Token from cookie exists in Redis
   - Token hasn't expired

3. **Session Termination**: On logout:
   - Redis entry is deleted
   - Cookie is invalidated
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

### Development

For local development:

1. Install frontend dependencies:
```bash
cd app1
npm install
cd ../app2
npm install
```

2. Install backend dependencies:
```bash
cd auth-service
pip install -r requirements.txt
```

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
    max_age=3600,
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

3. **Token Management**:
   - Short-lived tokens
   - Redis for central session control
   - Secure token generation

## Production Considerations

For production deployment:

1. Enable HTTPS:
   - Update cookie settings (secure=True)
   - Configure SSL in Nginx
   - Update CORS settings

2. Redis Security:
   - Enable authentication
   - Configure persistence
   - Set up replication

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
   - Check Redis connection
   - Verify token expiration
   - Check cookie domain settings

3. **Cross-Origin Issues**:
   - Verify CORS configuration
   - Check allowed origins
   - Ensure credentials are enabled

