from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import jwt
from datetime import datetime, timedelta
import zoneinfo
import os
import logging
import base64
import hashlib
import hmac

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
JWT_SECRET = os.getenv("JWT_SECRET", "your_secret_key_here")
TOKEN_EXPIRY = 1800  # 30 minutes in seconds
RWANDA_TZ = zoneinfo.ZoneInfo("Africa/Kigali")

# Test user credentials
TEST_USER = {
    "username": "testuser",
    "name": "Test User",
    "password_hash": 'pbkdf2_sha256$600000$kjDznrSz6fGFIJfWsQOns8$PtSj/2mBBmrB402bNRZTwC6XkLwon9QLvOZGinl1a+Y=',
}


class DjangoPasswordVerifier:
    """Matches Django's PBKDF2PasswordHasher verification"""

    @staticmethod
    def verify_password(password, encoded):
        """Verify if the given password matches the encoded hash from Django"""
        try:
            # Remove any whitespace
            encoded = encoded.strip()

            # Split the encoded hash into its components
            parts = encoded.split("$")
            if len(parts) != 4:
                logger.error(f"Invalid hash format. Got {len(parts)} parts, expected 4")
                logger.error(f"Parts: {parts}")
                return False

            algorithm = parts[0]
            iterations = int(parts[1])
            salt = parts[2]
            stored_hash = parts[3]

            logger.debug("=== Password Verification Details ===")
            logger.debug(f"Input password: {password}")
            logger.debug(f"Algorithm: {algorithm}")
            logger.debug(f"Iterations: {iterations}")
            logger.debug(f"Salt: {salt}")
            logger.debug(f"Stored hash: {stored_hash}")

            # Prepare password and salt
            password_bytes = password.encode()
            salt_bytes = salt.encode("ascii")

            # Calculate hash using exact same parameters as Django
            calculated_hash = hashlib.pbkdf2_hmac(
                "sha256", password_bytes, salt_bytes, iterations, dklen=32
            )

            # Encode the calculated hash to base64
            calculated_b64 = base64.b64encode(calculated_hash).decode("ascii").strip()

            logger.debug(f"Calculated hash (base64): {calculated_b64}")
            logger.debug(f"Stored hash: {stored_hash}")
            logger.debug(
                f"Hashes match: {hmac.compare_digest(stored_hash.encode('ascii'), calculated_b64.encode('ascii'))}"
            )

            # Compare the calculated hash with the stored hash
            return hmac.compare_digest(
                stored_hash.encode("ascii"), calculated_b64.encode("ascii")
            )

        except Exception as e:
            logger.error(f"Password verification error: {str(e)}")
            logger.exception("Full traceback:")
            return False


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
        secure=False,
        max_age=0,
        domain=COOKIE_DOMAIN,
        path="/",
        expires=datetime.utcnow() - timedelta(days=1),
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

        logger.debug(f"Login attempt for username: {username}")

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        # Check if user exists
        if username == TEST_USER["username"]:
            logger.debug("User found, verifying password...")

            # Verify password using Django's password hasher
            password_valid = DjangoPasswordVerifier.verify_password(
                password, TEST_USER["password_hash"]
            )

            if password_valid:
                logger.debug("Password verified successfully")
                token, exp = create_token(username)
                current_time = get_rwanda_time()

                response = make_response(
                    jsonify(
                        {
                            "token": token,
                            "user": {"username": username, "name": TEST_USER["name"]},
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
            else:
                logger.warning("Password verification failed")
                return jsonify({"error": "Invalid credentials"}), 401
        else:
            logger.warning(f"User not found: {username}")
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
