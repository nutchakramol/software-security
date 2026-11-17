#!/usr/bin/env python3
"""Task 5: migrate legacy MD5 password hashes to argon2id on login."""
import hashlib
import hmac
import sqlite3

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()  # argon2id, salted automatically


def legacy_md5(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def seed_legacy_user(db: sqlite3.Connection, username: str, password: str) -> None:
    """Simulate an old row created before the upgrade."""
    db.execute(
        "INSERT INTO users (username, pw_hash) VALUES (?, ?)",
        (username, legacy_md5(password)),
    )
    db.commit()


def get_hash(db: sqlite3.Connection, username: str) -> str | None:
    row = db.execute(
        "SELECT pw_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    return row[0] if row else None


def set_hash(db: sqlite3.Connection, username: str, new_hash: str) -> None:
    db.execute(
        "UPDATE users SET pw_hash = ? WHERE username = ?", (new_hash, username)
    )
    db.commit()


def login(db: sqlite3.Connection, username: str, password: str) -> bool:
    stored = get_hash(db, username)
    if stored is None:
        return False

    # Already migrated: normal argon2id verification.
    if stored.startswith("$argon2id$"):
        try:
            return ph.verify(stored, password)
        except VerifyMismatchError:
            return False

    # Legacy row: the only moment we know the real password is here, at login.
    # Compare in constant time so the check does not leak the hash byte by byte.
    if not hmac.compare_digest(legacy_md5(password), stored):
        return False  # wrong password: refuse and change nothing

    # Correct password: upgrade the row to argon2id right now.
    set_hash(db, username, ph.hash(password))
    return True


def check(label: str, condition: bool, results: list) -> None:
    results.append(condition)
    print(f"{'PASS' if condition else 'FAIL'} - {label}")


def main() -> None:
    db = sqlite3.connect(":memory:")
    db.execute(
        "CREATE TABLE users (username TEXT PRIMARY KEY, pw_hash TEXT NOT NULL)"
    )
    seed_legacy_user(db, "alice", "correct-horse")
    results: list = []

    # 1. Legacy user, wrong password is refused and row is untouched.
    before = get_hash(db, "alice")
    check("legacy user, wrong password refused",
          login(db, "alice", "wrong-pass") is False, results)
    check("wrong password does not change the stored hash",
          get_hash(db, "alice") == before, results)

    # 2. Legacy user, correct password succeeds and is upgraded.
    check("legacy user, correct password accepted",
          login(db, "alice", "correct-horse") is True, results)
    check("row upgraded to argon2id after login",
          get_hash(db, "alice").startswith("$argon2id$"), results)

    # 3. Migrated user still works, and wrong password is still refused.
    check("migrated user, correct password accepted",
          login(db, "alice", "correct-horse") is True, results)
    check("migrated user, wrong password refused",
          login(db, "alice", "wrong-pass") is False, results)

    # 4. Unknown user is refused.
    check("unknown user refused", login(db, "bob", "x") is False, results)

    print("ALL PASS" if all(results) else "SOME FAILED")


if __name__ == "__main__":
    main()