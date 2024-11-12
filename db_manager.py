#!/usr/bin/env python3
import sqlite3
import argparse
import logging
import sys
from datetime import datetime
import os
import json
import requests
from typing import Dict, List

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Constants
DB_PATH = "/Users/placideirandora/CODING/WiFI-Captive_Portal/ared.db"
API_URL = "https://app-ared-api-dev-south-africa-001.shirikihub.com/api/v1/yocto/router-associated-users/"


class DatabaseManager:
    def __init__(self):
        self.db_path = DB_PATH
        self.conn = None
        self.cursor = None

    def connect(self):
        """Establish database connection"""
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.cursor = self.conn.cursor()
            logger.info(f"Connected to database: {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Database connection error: {e}")
            sys.exit(1)

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")

    def check_tables(self):
        """List all tables and their row counts"""
        try:
            # Get all tables
            self.cursor.execute(
                """
                SELECT name FROM sqlite_master 
                WHERE type='table' 
                ORDER BY name;
            """
            )
            tables = self.cursor.fetchall()

            if not tables:
                print("\nNo tables found in database")
                return []

            print("\nDatabase Tables:")
            print("-" * 60)
            print(f"{'Table Name':<30} {'Row Count':<15} {'Columns':<15}")
            print("-" * 60)

            for table in tables:
                table_name = table[0]
                # Get row count
                self.cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                count = self.cursor.fetchone()[0]

                # Get column count
                self.cursor.execute(f"PRAGMA table_info({table_name})")
                columns = len(self.cursor.fetchall())

                print(f"{table_name:<30} {count:<15} {columns:<15}")

            return tables

        except sqlite3.Error as e:
            logger.error(f"Error checking tables: {e}")
            return []

    def create_users_table(self, drop_existing=False):
        """Create the users table"""
        try:
            if drop_existing:
                logger.warning("Dropping existing users table...")
                self.cursor.execute("DROP TABLE IF EXISTS users")

            self.cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    first_name TEXT NOT NULL,
                    last_name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    date_joined TIMESTAMP NOT NULL,
                    last_sync TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Create index on email for faster lookups
            self.cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_users_email 
                ON users(email)
            """
            )

            self.conn.commit()
            logger.info("Users table created successfully")

            # Show table structure
            print("\nTable Structure:")
            self.cursor.execute("PRAGMA table_info(users)")
            columns = self.cursor.fetchall()
            print("-" * 60)
            print(f"{'Column':<20} {'Type':<10} {'Nullable':<10} {'Default':<20}")
            print("-" * 60)
            for col in columns:
                print(
                    f"{col[1]:<20} {col[2]:<10} {'No' if col[3] else 'Yes':<10} {col[4] if col[4] else 'None':<20}"
                )

            return True
        except sqlite3.Error as e:
            logger.error(f"Error creating users table: {e}")
            return False

    def fetch_and_store_users(self, admin_email: str):
        """Fetch users from API and store them in the database"""
        try:
            # Make API request
            logger.info(f"Fetching users for admin email: {admin_email}")
            logger.info(f"Using API URL: {API_URL}")

            response = requests.get(f"{API_URL}?email={admin_email}")
            response.raise_for_status()
            data = response.json()

            # Begin transaction
            self.cursor.execute("BEGIN TRANSACTION")

            # Store associated users
            users = data.get("associated_users", [])
            logger.info(f"Found {len(users)} users to process")

            for user in users:
                try:
                    self.cursor.execute(
                        """
                        INSERT INTO users (
                            first_name, last_name, role, email, password, 
                            date_joined, last_sync
                        ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                        ON CONFLICT(email) DO UPDATE SET
                            first_name = excluded.first_name,
                            last_name = excluded.last_name,
                            role = excluded.role,
                            password = excluded.password,
                            date_joined = excluded.date_joined,
                            last_sync = CURRENT_TIMESTAMP
                    """,
                        (
                            user["first_name"],
                            user["last_name"],
                            user["role"],
                            user["email"],
                            user["password"],
                            user["date_joined"],
                        ),
                    )
                    logger.debug(f"Processed user: {user['email']}")
                except sqlite3.Error as e:
                    logger.error(f"Error storing user {user['email']}: {e}")

            # Commit transaction
            self.conn.commit()
            logger.info(f"Successfully stored {len(users)} users")

            # Show updated user count
            self.cursor.execute("SELECT COUNT(*) FROM users")
            total_users = self.cursor.fetchone()[0]
            print(f"\nTotal users in database: {total_users}")

            return True

        except requests.RequestException as e:
            self.conn.rollback()
            logger.error(f"API request failed: {e}")
            return False
        except sqlite3.Error as e:
            self.conn.rollback()
            logger.error(f"Database error: {e}")
            return False
        except Exception as e:
            self.conn.rollback()
            logger.error(f"Unexpected error: {e}")
            return False

    def list_users(self, limit=10):
        """List users with pagination"""
        try:
            self.cursor.execute(
                """
                SELECT 
                    first_name, last_name, email, role, 
                    date_joined, last_sync
                FROM users 
                ORDER BY date_joined DESC 
                LIMIT ?
            """,
                (limit,),
            )
            users = self.cursor.fetchall()

            if not users:
                print("\nNo users found in database")
                return []

            print(f"\nLast {limit} Users:")
            print("-" * 100)
            print(f"{'Name':<30} {'Email':<35} {'Role':<15} {'Joined':<20}")
            print("-" * 100)

            for user in users:
                first_name, last_name, email, role, date_joined, _ = user
                name = f"{first_name} {last_name}"
                try:
                    date_joined = datetime.fromisoformat(date_joined).strftime(
                        "%Y-%m-%d %H:%M"
                    )
                except:
                    date_joined = str(date_joined)

                print(f"{name:<30} {email:<35} {role:<15} {date_joined:<20}")

            return users
        except sqlite3.Error as e:
            logger.error(f"Error listing users: {e}")
            return []


def main():
    parser = argparse.ArgumentParser(
        description="Database Management Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  List tables:
    python {sys.argv[0]} tables

  Create users table:
    python {sys.argv[0]} create-table
    python {sys.argv[0]} create-table --drop

  Fetch users:
    python {sys.argv[0]} fetch-users --admin-email placideirandora@gmail.com

  List users:
    python {sys.argv[0]} list-users
    python {sys.argv[0]} list-users --limit 20

Database Path: {DB_PATH}
API URL: {API_URL}
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Tables command
    subparsers.add_parser("tables", help="List all database tables")

    # Create users table command
    create_table_parser = subparsers.add_parser(
        "create-table", help="Create users table"
    )
    create_table_parser.add_argument(
        "--drop", action="store_true", help="Drop existing table if it exists"
    )

    # Fetch users command
    fetch_parser = subparsers.add_parser(
        "fetch-users", help="Fetch and store users from API"
    )
    fetch_parser.add_argument(
        "--admin-email", required=True, help="Admin email to fetch users for"
    )

    # List users command
    list_parser = subparsers.add_parser("list-users", help="List stored users")
    list_parser.add_argument(
        "--limit", type=int, default=10, help="Number of users to show"
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    db_manager = DatabaseManager()

    try:
        db_manager.connect()

        if args.command == "tables":
            db_manager.check_tables()
        elif args.command == "create-table":
            db_manager.create_users_table(args.drop)
        elif args.command == "fetch-users":
            db_manager.fetch_and_store_users(args.admin_email)
        elif args.command == "list-users":
            db_manager.list_users(args.limit)

    finally:
        db_manager.close()


if __name__ == "__main__":
    main()
