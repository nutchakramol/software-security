"""
FIXED version of app.py — Week 2 remediation (Task 8).
Each change is tagged with its CWE.
"""
import os
import hashlib
import subprocess
import bcrypt  # CWE-327 fix: replace md5 with bcrypt
from flask import Flask, request

app = Flask(__name__)

# CWE-798 FIX: secrets moved to environment variables — never hardcode credentials
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
DB_PASSWORD = os.environ["DB_PASSWORD"]


@app.route("/user")
def user():
    name = request.args.get("name", "")
    import sqlite3
    con = sqlite3.connect("app.db")
    # CWE-89 FIX: parameterized query with ? placeholder — no string interpolation
    q = "SELECT * FROM users WHERE name = ?"
    return str(con.execute(q, (name,)).fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # CWE-78 FIX: shell=False + argument list — user input never reaches a shell
    return subprocess.check_output(["ping", "-c", "1", host], shell=False)


def store_password(pw):
    # CWE-327 FIX: bcrypt — salted, slow, purpose-built for passwords
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


if __name__ == "__main__":
    # CWE-489 FIX: debug=False in production; read from env var if needed
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
