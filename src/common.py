"""
Common utilities for SecureChat (hashing, protocol framing, rate limiting, replay protection).
"""
import os
import json
import time
import hmac
import hashlib
import threading
from dataclasses import dataclass

PBKDF2_ROUNDS = 200_000
SALT_BYTES = 16

def generate_salt() -> bytes:
    return os.urandom(SALT_BYTES)

def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ROUNDS)

def verify_password(password: str, salt: bytes, stored_hash: bytes) -> bool:
    calc = hash_password(password, salt)
    return hmac.compare_digest(calc, stored_hash)

# Message framing: JSON per line
def make_message(msg_type: str, payload: dict, counter: int) -> str:
    obj = {
        'type': msg_type,
        'counter': counter,
        'payload': payload,
        'ts': time.time()
    }
    # keep the newline so server/clients read complete JSON frames
    return json.dumps(obj) + '\n'

def parse_message(raw: str) -> dict:
    return json.loads(raw)

@dataclass
class TokenBucket:
    capacity: int
    fill_rate: float  # tokens per second
    tokens: float = 0.0
    timestamp: float = 0.0

    def __post_init__(self):
        self.tokens = self.capacity
        self.timestamp = time.time()
        self._lock = threading.Lock()

    def consume(self, amount: float = 1.0) -> bool:
        with self._lock:
            now = time.time()
            delta = now - self.timestamp
            self.timestamp = now
            self.tokens = min(self.capacity, self.tokens + delta * self.fill_rate)
            if self.tokens >= amount:
                self.tokens -= amount
                return True
            return False

class ReplayWindow:
    """Simple monotonic counter enforcement."""
    def __init__(self):
        self._expected = 1
        self._lock = threading.Lock()

    def check_and_advance(self, counter: int) -> bool:
        with self._lock:
            if counter == self._expected:
                self._expected += 1
                return True
            return False