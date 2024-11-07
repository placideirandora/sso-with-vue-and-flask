from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import jwt
from datetime import datetime, timedelta
import zoneinfo
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
TOKEN_EXPIRY = 1800  # 30 minutes in seconds

# Set Rwanda timezone
RWANDA_TZ = zoneinfo.ZoneInfo("Africa/Kigali")


def get_rwanda_time():
    """Get current time in Rwanda."""
    return datetime.now(RWANDA_TZ)


def create_token(username):
    """Create a new JWT token with proper expiration."""
    now = get_rwanda_time()
    exp = now + timedelta(seconds=TOKEN_EXPIRY)

    now_timestamp = int(now.timestamp())
    exp_timestamp = int(exp.timestamp())

    logger.debug(f"Token Creation Details (Rwanda Time):")
    logger.debug(f"Current time (Rwanda): {now.isoformat()}")
    logger.debug(f"Expiry time (Rwanda): {exp.isoformat()}")
    logger.debug(f"Time difference: {TOKEN_EXPIRY} seconds")

    token = jwt.encode(
        {
            "sub": username,
            "exp": exp_timestamp,
            "iat": now_timestamp,
            "tz": "Africa/Kigali",
        },
        JWT_SECRET,
        algorithm="HS256",
    )
    return token, exp


def verify_token(token):
    """Verify token validity."""
    try:
        current_time = get_rwanda_time()
        current_timestamp = int(current_time.timestamp())

        logger.debug(f"Verification time (Rwanda): {current_time.isoformat()}")

        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])

        exp_time = datetime.fromtimestamp(payload["exp"], RWANDA_TZ)
        logger.debug(f"Token expiration time: {exp_time.isoformat()}")

        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        raise
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {str(e)}")
        raise


def clear_auth_cookie(response):
    """Helper function to clear authentication cookie consistently."""
    response.set_cookie(
        "access_token",
        "",
        httponly=True,
        samesite="Lax",
        secure=False,  # Match the login setting
        max_age=0,
        domain=COOKIE_DOMAIN,
        path="/",
        expires=datetime.utcnow() - timedelta(days=1),  # Force immediate expiration
    )
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
            token, exp = create_token(username)
            current_time = get_rwanda_time()

            response = make_response(
                jsonify(
                    {
                        "token": token,
                        "user": {"username": username, "name": "Test User"},
                        "expires": exp.isoformat(),
                        "current_time": current_time.isoformat(),
                        "expiry_seconds": TOKEN_EXPIRY,
                        "timezone": "Africa/Kigali (CAT/UTC+2)",
                    }
                )
            )

            # Set the cookie with consistent settings
            response.set_cookie(
                "access_token",
                token,
                httponly=True,
                samesite="Lax",
                secure=False,
                max_age=TOKEN_EXPIRY,
                domain=COOKIE_DOMAIN,
                path="/",
                expires=exp,
            )

            response.headers.add(
                "Access-Control-Allow-Origin", request.headers.get("Origin")
            )
            response.headers.add("Access-Control-Allow-Credentials", "true")
            response.headers.add("Access-Control-Expose-Headers", "Set-Cookie")

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

    token = request.cookies.get("access_token")

    if not token:
        logger.warning("No token in cookies")
        return jsonify({"error": "No token provided"}), 401

    try:
        current_time = get_rwanda_time()

        payload = verify_token(token)
        username = payload["sub"]
        exp_timestamp = payload["exp"]

        exp_time = datetime.fromtimestamp(exp_timestamp, RWANDA_TZ)
        time_until_expiry = exp_timestamp - int(current_time.timestamp())

        response = make_response(
            jsonify(
                {
                    "authenticated": True,
                    "user": {"username": username, "name": "Test User"},
                    "exp": exp_time.isoformat(),
                    "current_time": current_time.isoformat(),
                    "seconds_until_expiry": time_until_expiry,
                    "timezone": "Africa/Kigali (CAT/UTC+2)",
                }
            )
        )

        response.headers.add(
            "Access-Control-Allow-Origin", request.headers.get("Origin")
        )
        response.headers.add("Access-Control-Allow-Credentials", "true")

        return response

    except jwt.ExpiredSignatureError:
        # Clear the expired cookie
        response = make_response(
            jsonify(
                {
                    "error": "Token has expired",
                    "code": "token_expired",
                    "current_time": get_rwanda_time().isoformat(),
                    "timezone": "Africa/Kigali (CAT/UTC+2)",
                }
            ),
            401,
        )
        return clear_auth_cookie(response)
    except jwt.InvalidTokenError as e:
        # Clear the invalid cookie
        response = make_response(
            jsonify(
                {"error": "Invalid token", "code": "token_invalid", "details": str(e)}
            ),
            401,
        )
        return clear_auth_cookie(response)
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
        response = make_response(jsonify({"message": "Successfully logged out"}))

        # Clear the auth cookie using the helper function
        response = clear_auth_cookie(response)

        # Set CORS headers
        response.headers.add(
            "Access-Control-Allow-Origin", request.headers.get("Origin")
        )
        response.headers.add("Access-Control-Allow-Credentials", "true")

        return response

    except Exception as e:
        logger.exception("Logout error")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
