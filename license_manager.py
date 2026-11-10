#!/usr/bin/env python3
"""
license_manager.py - Asymmetric Ed25519 offline license generation & validation.
Zero phone-home network calls: completely air-gapped verification.
"""

import base64
import json
import time
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# --- PUBLIC KEY EMBEDDED IN CLIENT BINARY ---
DEFAULT_PUBLIC_KEY_B64 = "MCowBQYDK2VwAyEA4P9NqH3+F5w5e6Z7a8b9c0d1e2f3a4b5c6d7e8f9a0b="


class LicenseAuthority:
    """Used exclusively on your secure Stripe/LemonSqueezy server to issue licenses."""
    def __init__(self, private_key: ed25519.Ed25519PrivateKey = None):
        self.private_key = private_key or ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def export_public_key_b64(self) -> str:
        raw_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return base64.b64encode(raw_bytes).decode('utf-8')

    def issue_license(self, customer_name: str, tier: str = "pro", valid_days: int = 365) -> str:
        expiry_timestamp = int(time.time()) + (valid_days * 86400)
        payload = {
            "sub": customer_name,
            "tier": tier,
            "exp": expiry_timestamp,
            "iat": int(time.time()),
            "features": ["synthetic_mode", "unlimited_volume", "jsonl_llm_pipeline"]
        }
        payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        signature = self.private_key.sign(payload_bytes)

        payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode('utf-8')
        sig_b64 = base64.urlsafe_b64encode(signature).decode('utf-8')
        return f"PII-{payload_b64}.{sig_b64}"


class LicenseValidator:
    """Embedded inside pii-scrub binary to verify customer licenses locally."""
    def __init__(self, public_key_raw_b64: str):
        key_bytes = base64.b64decode(public_key_raw_b64)
        self.public_key = ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)

    def verify_license(self, license_key: str) -> dict:
        if not license_key or not license_key.startswith("PII-"):
            raise ValueError("Invalid license format. Must start with PII-")

        token = license_key[4:]
        parts = token.split(".")
        if len(parts) != 2:
            raise ValueError("Malformed license key structure.")

        payload_b64, sig_b64 = parts
        try:
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            signature = base64.urlsafe_b64decode(sig_b64)
        except Exception as e:
            raise ValueError(f"Base64 decoding failed: {e}")

        # Verify mathematical signature
        try:
            self.public_key.verify(signature, payload_bytes)
        except Exception:
            raise ValueError("Cryptographic signature verification failed! License was forged or corrupted.")

        payload = json.loads(payload_bytes.decode('utf-8'))
        now = int(time.time())
        if payload.get("exp", 0) < now:
            exp_date = datetime.fromtimestamp(payload['exp'], tz=timezone.utc).strftime('%Y-%m-%d')
            raise ValueError(f"License expired on {exp_date}. Please renew at https://piiscrub.dev")

        return payload
