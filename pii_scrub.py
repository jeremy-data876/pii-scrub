#!/usr/bin/env python3
"""
pii_scrub.py - Enterprise-grade, zero-retention streaming PII redaction engine.
Supports raw streams, CSV/TSV dumps, and JSON Lines (LLM fine-tuning pipelines).
Includes peer-reviewed offline license verification (Ed25519).
"""

import sys
import os
import re
import csv
import json
import hashlib
import hmac
import warnings
from typing import List, Optional, Any, Set

from license_manager import LicenseValidator

# Increase CSV field size limit for large database text columns
csv.field_size_limit(sys.maxsize)

# Hardcoded Vendor Public Verification Key (embedded in release binary)
EMBEDDED_VENDOR_PUB_KEY = "f1IiTvSXXpykRX6EBP1OuP0qE1G9Xn2bQvV8f0Z1m9c="

# --- TIER 1: Pre-compiled Regular Expressions ---
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
SSN_REGEX = re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b')
PHONE_REGEX = re.compile(r'(?:\+?1[-. ]?)?\(?([2-9]\d{2})\)?[-. ]?([2-9]\d{2})[-. ]?(\d{4})\b')
CARD_CANDIDATE_REGEX = re.compile(r'\b(?:\d[ -]*?){13,19}\b')


def is_valid_luhn(candidate: str) -> bool:
    """Validates candidate string against Luhn algorithm (MOD-10)."""
    digits = [int(c) for c in candidate if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
            
    return checksum % 10 == 0


class HardenedScrubEngine:
    def __init__(self, salt: Optional[str] = None, mode: str = "synthetic", is_pro: bool = False):
        if not salt:
            salt = os.getenv("PII_SCRUB_SALT")
        
        if not salt:
            warnings.warn(
                "SECURITY WARNING: No cryptographic salt provided via --salt or PII_SCRUB_SALT. "
                "Using default ephemeral salt.",
                RuntimeWarning,
                stacklevel=2
            )
            salt = "default_unseeded_dev_salt"

        self.salt = salt.encode('utf-8')
        self.is_pro = is_pro

        # Enforce tier capabilities
        if mode == "synthetic" and not is_pro:
            sys.stderr.write(
                "\n[NOTICE] Synthetic format-preserving mode is a Pro feature.\n"
                "Running in Community Masking mode ([EMAIL], [CARD]).\n"
                "To unlock schema-safe synthetic data, get a license at https://piiscrub.dev\n\n"
            )
            self.mode = "mask"
        else:
            self.mode = mode

    def _hash_token(self, raw_value: str, length: int = 8) -> str:
        clean = raw_value.strip().encode('utf-8')
        return hmac.new(self.salt, clean, hashlib.sha256).hexdigest()[:length]

    def _replace_email(self, match) -> str:
        raw = match.group(0)
        if self.mode == "mask":
            return "[EMAIL]"
        token = self._hash_token(raw, 8)
        return f"EMAIL_{token}" if self.mode == "pseudonymize" else f"user_{token}@synthetic.local"

    def _replace_phone(self, match) -> str:
        raw = match.group(0)
        if self.mode == "mask":
            return "[PHONE]"
        token = self._hash_token(raw, 4)
        return f"PHONE_{token}" if self.mode == "pseudonymize" else f"555-01{int(token, 16) % 100:02d}"

    def _replace_ssn(self, match) -> str:
        raw = match.group(0)
        if self.mode == "mask":
            return "[SSN]"
        token = self._hash_token(raw, 8)
        return f"SSN_{token}" if self.mode == "pseudonymize" else f"000-12-{int(token, 16) % 1000000:04d}"

    def _replace_card(self, match) -> str:
        raw = match.group(0)
        if not is_valid_luhn(raw):
            return raw
        if self.mode == "mask":
            return "[CARD]"
        token = self._hash_token(raw, 8)
        if self.mode == "pseudonymize":
            return f"CARD_{token}"
        last4 = int(token, 16) % 10000
        return f"4000-0000-0000-{last4:04d}"

    def scrub_text(self, text: str) -> str:
        if not isinstance(text, str):
            return text
        text = EMAIL_REGEX.sub(self._replace_email, text)
        text = PHONE_REGEX.sub(self._replace_phone, text)
        text = SSN_REGEX.sub(self._replace_ssn, text)
        text = CARD_CANDIDATE_REGEX.sub(self._replace_card, text)
        return text

    def scrub_json_value(self, data: Any, target_keys_lower: Optional[Set[str]] = None) -> Any:
        if isinstance(data, dict):
            return {
                k: self.scrub_json_value(v, target_keys_lower)
                if (target_keys_lower is None or k.lower() in target_keys_lower)
                else v
                for k, v in data.items()
            }
        elif isinstance(data, list):
            return [self.scrub_json_value(item, target_keys_lower) for item in data]
        elif isinstance(data, str):
            return self.scrub_text(data)
        return data


# --- STREAMING PROCESSORS ---

def process_raw(engine: HardenedScrubEngine):
    for line in sys.stdin:
        sys.stdout.write(engine.scrub_text(line))
    sys.stdout.flush()


def process_jsonl(engine: HardenedScrubEngine, target_keys: Optional[List[str]] = None, on_error: str = "warn"):
    target_keys_lower = {k.lower() for k in target_keys} if target_keys else None

    for line_num, line in enumerate(sys.stdin, 1):
        clean_line = line.strip()
        if not clean_line:
            continue
        try:
            record = json.loads(clean_line)
            scrubbed = engine.scrub_json_value(record, target_keys_lower)
            sys.stdout.write(json.dumps(scrubbed, ensure_ascii=False) + "\n")
        except json.JSONDecodeError as e:
            if on_error == "fail":
                sys.stderr.write(f"Error: line {line_num} is malformed JSON ({e}).\n")
                sys.exit(1)
            elif on_error == "warn":
                sys.stderr.write(f"Warning: line {line_num} invalid JSON. Passing through unscrubbed.\n")
                sys.stdout.write(line)
            elif on_error == "skip":
                continue
    sys.stdout.flush()


def process_csv(engine: HardenedScrubEngine, target_columns: Optional[List[str]] = None, on_error: str = "warn"):
    reader = csv.reader(sys.stdin)
    writer = csv.writer(sys.stdout)

    try:
        header = next(reader)
    except StopIteration:
        return

    writer.writerow(header)

    col_indices = None
    if target_columns:
        col_indices = set()
        header_lower_map = {col_name.lower(): idx for idx, col_name in enumerate(header)}
        for col_name in target_columns:
            target_lower = col_name.lower()
            if target_lower in header_lower_map:
                col_indices.add(header_lower_map[target_lower])
            elif on_error == "fail":
                sys.stderr.write(f"Error: column '{col_name}' missing from header.\n")
                sys.exit(1)
            elif on_error == "warn":
                sys.stderr.write(f"Warning: target column '{col_name}' not found in CSV header.\n")

    for row in reader:
        scrubbed_row = []
        for idx, val in enumerate(row):
            if col_indices is None or idx in col_indices:
                scrubbed_row.append(engine.scrub_text(val))
            else:
                scrubbed_row.append(val)
        writer.writerow(scrubbed_row)
    sys.stdout.flush()


def check_license(license_key: Optional[str]) -> bool:
    """Validates license offline. Returns True if valid Pro license."""
    if not license_key:
        license_key = os.getenv("PII_SCRUB_LICENSE")
    if not license_key:
        return False
    
    try:
        validator = LicenseValidator(EMBEDDED_VENDOR_PUB_KEY)
        info = validator.verify_license(license_key)
        sys.stderr.write(f"[INFO] Licensed to {info['sub']} ({info['tier'].upper()} Tier)\n")
        return True
    except Exception as e:
        sys.stderr.write(f"[LICENSE WARNING] {e}. Falling back to Community Tier.\n")
        return False


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Zero-retention multi-format PII scrubber")
    parser.add_argument("--version", action="version", version="pii-scrub v1.0.0")
    parser.add_argument("--format", choices=["raw", "jsonl", "csv"], default="raw",
                        help="Stream format: 'raw' (default), 'jsonl', or 'csv'")
    parser.add_argument("--mode", choices=["mask", "pseudonymize", "synthetic"], default="synthetic",
                        help="Sanitization mode")
    parser.add_argument("--salt", default=None,
                        help="Cryptographic salt")
    parser.add_argument("--license", default=None,
                        help="Offline Pro license key (or set PII_SCRUB_LICENSE)")
    parser.add_argument("--columns", default=None,
                        help="Comma-separated column names for CSV mode")
    parser.add_argument("--keys", default=None,
                        help="Comma-separated keys for JSONL mode")
    parser.add_argument("--on-error", choices=["skip", "warn", "fail"], default="warn",
                        help="Error handling policy: 'warn', 'skip', or 'fail'")
    args = parser.parse_args()

    is_pro = check_license(args.license)
    engine = HardenedScrubEngine(salt=args.salt, mode=args.mode, is_pro=is_pro)

    try:
        if args.format == "raw":
            process_raw(engine)
        elif args.format == "jsonl":
            keys = [k.strip() for k in args.keys.split(",")] if args.keys else None
            process_jsonl(engine, target_keys=keys, on_error=args.on_error)
        elif args.format == "csv":
            cols = [c.strip() for c in args.columns.split(",")] if args.columns else None
            process_csv(engine, target_columns=cols, on_error=args.on_error)
    except BrokenPipeError:
        sys.stderr.close()


if __name__ == "__main__":
    main()
