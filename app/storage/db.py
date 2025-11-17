"""
MySQL user store (salted SHA-256 passwords).

Table schema:

    CREATE TABLE users (
        email VARCHAR(255) PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        salt VARBINARY(16) NOT NULL,
        pwd_hash CHAR(64) NOT NULL
    );
"""

import os
import argparse
import sys
import pymysql
from hashlib import sha256
from typing import Optional, Tuple


def get_db_config():
    """Read DB config from environment variables (see .env.example)."""
    host = os.getenv("DB_HOST", "localhost")
    port = int(os.getenv("DB_PORT", "3306"))
    name = os.getenv("DB_NAME", "securechat")
    user = os.getenv("DB_USER", "scuser")
    password = os.getenv("DB_PASSWORD", "scpass")
    return host, port, name, user, password


def get_connection():
    """Open a new PyMySQL connection using env config."""
    host, port, name, user, password = get_db_config()
    return pymysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=name,
        autocommit=True,
    )


def init_db() -> None:
    """
    Initialize the 'users' table if it does not exist.
    Called via: python -m app.storage.db --init
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    email VARCHAR(255) PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    salt VARBINARY(16) NOT NULL,
                    pwd_hash CHAR(64) NOT NULL
                );
                """
            )
        print("[DB] users table ensured.")
    finally:
        conn.close()


def _hash_password(salt: bytes, password: str) -> str:
    """
    Compute hex(SHA256(salt || password)).
    """
    if isinstance(password, str):
        password_bytes = password.encode("utf-8")
    else:
        password_bytes = password
    digest = sha256(salt + password_bytes).hexdigest()
    return digest


def create_user(email: str, username: str, password: str) -> bool:
    """
    Create a new user with random 16-byte salt and salted SHA-256 hash.

    Returns True on success, False if user/email already exists.
    """
    conn = get_connection()
    try:
        salt = os.urandom(16)
        pwd_hash = _hash_password(salt, password)

        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (email, username, salt, pwd_hash)
                VALUES (%s, %s, %s, %s)
                """,
                (email, username, salt, pwd_hash),
            )
        return True
    except pymysql.err.IntegrityError:
        # Duplicate email or username
        return False
    finally:
        conn.close()


def _get_user_record(email: str) -> Optional[Tuple[str, bytes, str, str]]:
    """
    Return (email, username, salt, pwd_hash) or None.
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT email, username, salt, pwd_hash FROM users WHERE email = %s",
                (email,),
            )
            row = cur.fetchone()
            if not row:
                return None
            # row = (email, username, salt_bytes, pwd_hash_str)
            return row  # type: ignore[return-value]
    finally:
        conn.close()


def verify_user(email: str, password: str) -> Optional[str]:
    """
    Verify user credentials.

    Returns:
        - username (str) if email+password correct
        - None if invalid or user not found
    """
    record = _get_user_record(email)
    if not record:
        return None

    _email, username, salt, stored_hash = record
    computed = _hash_password(salt, password)

    # Constant-time-ish compare (still Python-level but better than naive ==)
    if len(computed) != len(stored_hash):
        return None

    mismatch = 0
    for a, b in zip(computed, stored_hash):
        if a != b:
            mismatch += 1
    if mismatch != 0:
        return None

    return username


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--init",
        action="store_true",
        help="Initialize the users table in the database",
    )
    args = parser.parse_args(argv)

    if args.init:
        init_db()
    else:
        parser.print_help()


if __name__ == "__main__":
    main(sys.argv[1:])
