from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import jwt
from datetime import datetime, timedelta
import zoneinfo
import os
import logging
import time

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
TOKEN_EXPIRY = 600  # 1 minute in seconds

# Set Rwanda timezone
RWANDA_TZ = zoneinfo.ZoneInfo("Africa/Kigali")


def get_rwanda_time():
    """Get current time in Rwanda."""
    return datetime.now(RWANDA_TZ)


def create_token(username):
    """Create a new JWT token with proper expiration."""
    # Get current Rwanda time
    now = get_rwanda_time()
    exp = now + timedelta(seconds=TOKEN_EXPIRY)

    # Convert to timestamps
    now_timestamp = int(now.timestamp())
    exp_timestamp = int(exp.timestamp())

    logger.debug(f"Token Creation Details (Rwanda Time):")
    logger.debug(f"Current time (Rwanda): {now.isoformat()}")
    logger.debug(f"Expiry time (Rwanda): {exp.isoformat()}")
    logger.debug(f"Current timestamp: {now_timestamp}")
    logger.debug(f"Expiry timestamp: {exp_timestamp}")
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
        # Get current Rwanda time
        current_time = get_rwanda_time()
        current_timestamp = int(current_time.timestamp())

        logger.debug(
            f"Verification time (Rwanda): {current_time.isoformat()} ({current_timestamp})"
        )

        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], leeway=0)

        # Convert expiration timestamp to Rwanda time
        exp_time = datetime.fromtimestamp(payload["exp"], RWANDA_TZ)
        logger.debug(f"Token Details (Rwanda Time):")
        logger.debug(f"Expiration time: {exp_time.isoformat()}")
        logger.debug(
            f"Time until expiration: {payload['exp'] - current_timestamp} seconds"
        )

        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        raise
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {str(e)}")
        raise


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
        current_timestamp = int(current_time.timestamp())

        payload = verify_token(token)
        username = payload["sub"]
        exp_timestamp = payload["exp"]

        exp_time = datetime.fromtimestamp(exp_timestamp, RWANDA_TZ)
        time_until_expiry = exp_timestamp - current_timestamp

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
        return (
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
    except jwt.InvalidTokenError as e:
        return (
            jsonify(
                {"error": "Invalid token", "code": "token_invalid", "details": str(e)}
            ),
            401,
        )
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

        # Delete the cookie
        response.set_cookie(
            "access_token",
            "",
            httponly=True,
            samesite="Lax",
            secure=True,
            max_age=0,
            domain=COOKIE_DOMAIN,
            path="/",
            expires=0,
        )

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
