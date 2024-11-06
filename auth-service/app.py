from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import redis
import jwt
from datetime import datetime, timedelta
import os
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(
    app,
    resources={
        r"/*": {
            "origins": ["http://app1.sso.local:8080", "http://app2.sso.local:8081"],
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
            "supports_credentials": True,
            "expose_headers": ["Set-Cookie"],
        }
    },
)

COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN", ".sso.local")

# Constants
JWT_SECRET = os.getenv("JWT_SECRET", "your_secret_key_here")
TOKEN_EXPIRY = 3600  # 1 hour

# Redis connection with error handling
try:
    redis_client = redis.Redis(
        host=os.getenv("REDIS_HOST", "redis"),
        port=int(os.getenv("REDIS_PORT", 6379)),
        decode_responses=True,
    )
    redis_client.ping()  # Test connection
    logger.info("Redis connection successful")
except Exception as e:
    logger.error(f"Redis connection failed: {e}")
    raise


def log_request_details():
    logger.debug("=== Request Details ===")
    logger.debug(f"Method: {request.method}")
    logger.debug(f"URL: {request.url}")
    logger.debug(f"Headers: {dict(request.headers)}")
    logger.debug(f"Cookies: {request.cookies}")
    logger.debug("===================")


def log_response_details(response):
    logger.debug("=== Response Details ===")
    logger.debug(f"Status: {response.status_code}")
    logger.debug(f"Headers: {dict(response.headers)}")
    logger.debug(f"Set-Cookie header: {response.headers.get('Set-Cookie')}")
    logger.debug("===================")
    return response


@app.before_request
def log_request_info():
    logger.debug("--- New Request ---")
    logger.debug(f"Method: {request.method}")
    logger.debug(f"URL: {request.url}")
    logger.debug(f"Headers: {dict(request.headers)}")
    logger.debug(f"Cookies: {request.cookies}")
    if request.method == "OPTIONS":
        logger.debug("OPTIONS request received")
    elif request.get_json(silent=True):
        logger.debug(f"Body: {request.get_json()}")


@app.after_request
def log_response_info(response):
    logger.debug("--- Response ---")
    logger.debug(f"Status: {response.status}")
    logger.debug(f"Headers: {dict(response.headers)}")
    return response


@app.route("/auth/login", methods=["POST", "OPTIONS"])
def login():
    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add(
            "Access-Control-Allow-Origin", request.headers.get("Origin")
        )
        response.headers.add("Access-Control-Allow-Headers", "Content-Type")
        response.headers.add("Access-Control-Allow-Methods", "POST, OPTIONS")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        response.headers.add("Access-Control-Expose-Headers", "Set-Cookie")
        return response

    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if username == "testuser" and password == "password123":
            token = jwt.encode(
                {"sub": username, "exp": datetime.utcnow() + timedelta(seconds=3600)},
                "your_secret_key_here",
                algorithm="HS256",
            )

            response = make_response(
                jsonify(
                    {
                        "token": token,
                        "user": {"username": username, "name": "Test User"},
                    }
                )
            )

            # Set cookie with domain
            response.set_cookie(
                "access_token",
                token,
                httponly=True,
                samesite="Lax",
                secure=False,
                max_age=3600,
                domain=COOKIE_DOMAIN,
                path="/",
            )

            # CORS headers
            response.headers.add(
                "Access-Control-Allow-Origin", request.headers.get("Origin")
            )
            response.headers.add("Access-Control-Allow-Credentials", "true")
            response.headers.add("Access-Control-Expose-Headers", "Set-Cookie")

            logger.debug(f"Set-Cookie header: {response.headers.get('Set-Cookie')}")
            return response

        return jsonify({"error": "Invalid credentials"}), 401

    except Exception as e:
        logger.exception("Login error")
        return jsonify({"error": str(e)}), 500


@app.route("/auth/verify", methods=["GET", "OPTIONS"])
def verify():
    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add(
            "Access-Control-Allow-Origin", request.headers.get("Origin")
        )
        response.headers.add("Access-Control-Allow-Headers", "Content-Type")
        response.headers.add("Access-Control-Allow-Methods", "GET, OPTIONS")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        return response

    logger.debug(f"Cookies received: {request.cookies}")
    token = request.cookies.get("access_token")

    if not token:
        logger.warning("No token in cookies")
        return jsonify({"error": "No token provided"}), 401

    try:
        # Verify token
        payload = jwt.decode(token, "your_secret_key_here", algorithms=["HS256"])
        username = payload["sub"]

        response = make_response(
            jsonify(
                {
                    "authenticated": True,
                    "user": {"username": username, "name": "Test User"},
                }
            )
        )

        # Set CORS headers
        response.headers.add(
            "Access-Control-Allow-Origin", request.headers.get("Origin")
        )
        response.headers.add("Access-Control-Allow-Credentials", "true")

        return response

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    except Exception as e:
        logger.error(f"Verification error: {str(e)}")
        return jsonify({"error": str(e)}), 401


@app.route("/auth/logout", methods=["POST", "OPTIONS"])
def logout():
    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add(
            "Access-Control-Allow-Origin", request.headers.get("Origin")
        )
        response.headers.add("Access-Control-Allow-Headers", "Content-Type")
        response.headers.add("Access-Control-Allow-Methods", "POST, OPTIONS")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        return response

    try:
        # Get the token from cookies
        token = request.cookies.get("access_token")

        if token:
            # Remove session from Redis if you're using it
            redis_client.delete(f"session:{token}")

            # Create response
            response = make_response(jsonify({"message": "Successfully logged out"}))

            # Delete the cookie by setting max_age=0
            response.set_cookie(
                "access_token",
                "",
                httponly=True,
                samesite="Lax",
                secure=False,
                max_age=0,
                domain=COOKIE_DOMAIN,
                path="/",
            )

            # Set CORS headers
            response.headers.add(
                "Access-Control-Allow-Origin", request.headers.get("Origin")
            )
            response.headers.add("Access-Control-Allow-Credentials", "true")

            return response

        return jsonify({"message": "No session to logout"}), 200

    except Exception as e:
        logger.exception("Logout error")
        return jsonify({"error": str(e)}), 500


def handle_preflight():
    response = make_response()
    response.headers.add("Access-Control-Allow-Origin", request.headers.get("Origin"))
    response.headers.add("Access-Control-Allow-Headers", "*")
    response.headers.add("Access-Control-Allow-Methods", "POST, OPTIONS")
    response.headers.add("Access-Control-Allow-Credentials", "true")
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
