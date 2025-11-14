# """MySQL users table + salted hashing (no chat storage).""" 
# raise NotImplementedError("students: implement DB layer")



#!/usr/bin/env python3
"""

MySQL user store:
    users(email VARCHAR(255),
          username VARCHAR(255) UNIQUE,
          salt BINARY(16),
          pwd_hash CHAR(64))

Implements:
- create_user(email, username, salt_bytes, pwd_hash_hex)
- get_user_by_username(username)
- --init command to create table
"""

import mysql.connector
import argparse
import os
import sys
from dotenv import load_dotenv
import hmac


# ----------------------------------------------------------
# Load DB configuration from .env
# ----------------------------------------------------------

load_dotenv()

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "scuser")
DB_PASS = os.getenv("DB_PASS", "scpass")
DB_NAME = os.getenv("DB_NAME", "securechat")


def get_conn():
    """Return a MySQL connection object."""
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME
    )


# ----------------------------------------------------------
# INITIALIZATION
# ----------------------------------------------------------

def init_db():
    """Initialize 'users' table according to assignment specification."""
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email VARCHAR(255),
            username VARCHAR(255) UNIQUE,
            salt BINARY(16),
            pwd_hash CHAR(64)
        );
    """)

    conn.commit()
    cur.close()
    conn.close()
    print("[+] MySQL 'users' table created (or already existed).")


# ----------------------------------------------------------
# USER OPERATIONS
# ----------------------------------------------------------

def create_user(email: str, username: str, salt_bytes: bytes, pwd_hash_hex: str):
    """
    Store a new user.
    salt_bytes: 16-byte random
    pwd_hash_hex: 64-char hex string, SHA256(salt || password)
    """
    if not isinstance(salt_bytes, (bytes, bytearray)):
        raise ValueError("salt_bytes must be raw bytes")

    if len(salt_bytes) != 16:
        raise ValueError("salt must be 16 bytes")

    if len(pwd_hash_hex) != 64:
        raise ValueError("pwd_hash must be 64 hex characters")

    conn = get_conn()
    cur = conn.cursor()

    try:
        cur.execute("""
            INSERT INTO users (email, username, salt, pwd_hash)
            VALUES (%s, %s, %s, %s)
        """, (email, username, salt_bytes, pwd_hash_hex))
        conn.commit()
    finally:
        cur.close()
        conn.close()


def get_user_by_username(username: str):
    """
    Retrieve a user by username.
    Return dict: {email, username, salt, pwd_hash}
    or None if not found.
    """
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT email, username, salt, pwd_hash
        FROM users
        WHERE username = %s
    """, (username,))

    row = cur.fetchone()

    cur.close()
    conn.close()

    if row is None:
        return None

    email, username, salt_bytes, pwd_hash_hex = row
    return {
        "email": email,
        "username": username,
        "salt": salt_bytes,
        "pwd_hash": pwd_hash_hex
    }


# ----------------------------------------------------------
# MAIN (CLI)
# ----------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--init", action="store_true", help="Create users table")
    args = parser.parse_args()

    if args.init:
        init_db()
    else:
        print("Usage: python -m app.storage.db --init")


if __name__ == "__main__":
    main()
