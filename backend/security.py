"""Password hashing, session tokens and login throttling (standard library only)."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time

_N, _R, _P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, digest = stored.split("$")
        candidate = hashlib.scrypt(
            password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, bytes.fromhex(digest))


# Verified against when the email is unknown, so timing does not reveal valid accounts.
DUMMY_HASH = hash_password("dummy-password-for-timing")


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Only the hash of a session token is stored: a database leak does not leak sessions."""
    return hashlib.sha256(token.encode()).hexdigest()


class LoginThrottle:
    """Lock an email for `lock_seconds` after `max_failures` consecutive failures."""

    def __init__(self, max_failures: int = 5, lock_seconds: float = 60.0) -> None:
        self.max_failures = max_failures
        self.lock_seconds = lock_seconds
        self._failures: dict[str, tuple[int, float]] = {}
        self._lock = threading.Lock()

    def is_locked(self, key: str) -> bool:
        with self._lock:
            count, last = self._failures.get(key, (0, 0.0))
            if count >= self.max_failures and time.monotonic() - last < self.lock_seconds:
                return True
            if count >= self.max_failures:
                del self._failures[key]
            return False

    def failure(self, key: str) -> None:
        with self._lock:
            count, _ = self._failures.get(key, (0, 0.0))
            self._failures[key] = (count + 1, time.monotonic())

    def success(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
