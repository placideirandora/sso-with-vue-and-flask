import os
import sys
import jwt
import logging
import sqlite3
import base64
import hashlib
import hmac
from datetime import datetime, timedelta
import zoneinfo
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

# Configure logging
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize Flask app
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

# Configuration
COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN", ".sso.local")
JWT_SECRET = os.getenv("JWT_SECRET", "your_secret_key_here")
TOKEN_EXPIRY = 1800  # 30 minutes
RWANDA_TZ = zoneinfo.ZoneInfo("Africa/Kigali")
DB_PATH = os.getenv("DB_PATH", "/app/data/ared.db")


class DatabaseConnection:
    def __init__(self):
        self.conn = None
        self.cursor = None

    def __enter__(self):
        try:
            self.conn = sqlite3.connect(DB_PATH)
            self.cursor = self.conn.cursor()
            return self
        except sqlite3.Error as e:
            logger.error(f"Database connection error: {e}")
            raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            self.conn.close()


def get_user_by_email(email):
    """Retrieve user from database by email"""
    with DatabaseConnection() as db:
        try:
            db.cursor.execute(
                """
                SELECT 
                    email, 
                    first_name,
                    last_name,
                    role,
                    password,
                    date_joined
                FROM users 
                WHERE email = ?
            """,
                (email,),
            )
            user = db.cursor.fetchone()

            if user:
                return {
                    "email": user[0],
                    "first_name": user[1],
                    "last_name": user[2],
                    "role": user[3],
                    "password": user[4],
                    "date_joined": user[5],
                }
            return None
        except sqlite3.Error as e:
            logger.error(f"Database error while fetching user: {e}")
            return None


class DjangoPasswordVerifier:
    @staticmethod
    def verify_password(password, encoded):
        """Verify password against Django's password hash"""
        try:
            encoded = encoded.strip()
            parts = encoded.split("$")

            if len(parts) != 4:
                logger.error(f"Invalid hash format. Got {len(parts)} parts, expected 4")
                return False

            algorithm, iterations, salt, stored_hash = parts
            iterations = int(iterations)

            logger.debug("Password verification details:")
            logger.debug(f"Algorithm: {algorithm}")
            logger.debug(f"Iterations: {iterations}")
            logger.debug(f"Salt: {salt}")

            # Calculate hash
            calculated_hash = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), salt.encode("ascii"), iterations, dklen=32
            )
            calculated_b64 = base64.b64encode(calculated_hash).decode("ascii").strip()

            # Compare hashes
            is_valid = hmac.compare_digest(
                stored_hash.encode("ascii"), calculated_b64.encode("ascii")
            )

            logger.debug(f"Password verification result: {is_valid}")
            return is_valid

        except Exception as e:
            logger.error(f"Password verification error: {str(e)}")
            return False


def create_token(user_data):
    """Create a new JWT token with user data"""
    try:
        now = datetime.now(RWANDA_TZ)
        exp = now + timedelta(seconds=TOKEN_EXPIRY)

        token = jwt.encode(
            {
                "sub": user_data["email"],
                "name": f"{user_data['first_name']} {user_data['last_name']}",
                "role": user_data["role"],
                "exp": int(exp.timestamp()),
                "iat": int(now.timestamp()),
                "tz": "Africa/Kigali",
            },
            JWT_SECRET,
            algorithm="HS256",
        )
        return token, exp
    except Exception as e:
        logger.error(f"Token creation error: {e}")
        raise


def verify_token(token):
    """Verify token validity"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        logger.debug(f"Token payload: {payload}")
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
        email = data.get("email")
        password = data.get("password")

        logger.debug(f"Login attempt for email: {email}")

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        # Get user from database
        user = get_user_by_email(email)
        if not user:
            logger.warning(f"User not found: {email}")
            return jsonify({"error": "Invalid credentials"}), 401

        # Verify password
        if not DjangoPasswordVerifier.verify_password(password, user["password"]):
            logger.warning(f"Invalid password for user: {email}")
            return jsonify({"error": "Invalid credentials"}), 401

        # Create token
        token, exp = create_token(user)

        # Create response
        response = make_response(
            jsonify(
                {
                    "user": {
                        "email": user["email"],
                        "name": f"{user['first_name']} {user['last_name']}",
                        "role": user["role"],
                    }
                }
            )
        )

        # Set cookie
        response.set_cookie(
            "access_token",
            token,
            httponly=True,
            samesite="Lax",
            secure=False,  # Set to True in production with HTTPS
            max_age=TOKEN_EXPIRY,
            domain=COOKIE_DOMAIN,
            path="/",
            expires=exp,
        )

        # Set CORS headers
        response.headers.add(
            "Access-Control-Allow-Origin", request.headers.get("Origin")
        )
        response.headers.add("Access-Control-Allow-Credentials", "true")
        response.headers.add("Access-Control-Expose-Headers", "Set-Cookie")

        logger.info(f"Login successful for user: {email}")
        return response

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

    try:
        token = request.cookies.get("access_token")
        if not token:
            logger.warning("No token in cookies")
            return jsonify({"error": "No token provided"}), 401

        # Verify token
        payload = verify_token(token)

        # Get fresh user data
        user = get_user_by_email(payload["sub"])
        if not user:
            logger.warning(f"User not found during verification: {payload['sub']}")
            return jsonify({"error": "User not found"}), 401

        response = make_response(
            jsonify(
                {
                    "authenticated": True,
                    "user": {
                        "email": user["email"],
                        "name": f"{user['first_name']} {user['last_name']}",
                        "role": user["role"],
                    },
                }
            )
        )

        response.headers.add(
            "Access-Control-Allow-Origin", request.headers.get("Origin")
        )
        response.headers.add("Access-Control-Allow-Credentials", "true")

        return response

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired", "code": "token_expired"}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({"error": "Invalid token", "code": "token_invalid"}), 401
    except Exception as e:
        logger.exception("Verification error")
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

        # Clear the cookie
        response.set_cookie(
            "access_token",
            "",
            httponly=True,
            samesite="Lax",
            secure=False,  # Set to True in production with HTTPS
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
    logger.info(f"Starting auth service...")
    logger.info(f"Database path: {DB_PATH}")

    # Verify database connection on startup
    try:
        with DatabaseConnection() as db:
            db.cursor.execute("SELECT COUNT(*) FROM users")
            count = db.cursor.fetchone()[0]
            logger.info(f"Connected to database. Total users: {count}")
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        sys.exit(1)

    app.run(host="0.0.0.0", port=5001, debug=True)
