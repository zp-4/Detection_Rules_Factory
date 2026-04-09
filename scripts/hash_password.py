#!/usr/bin/env python3
"""Print a password_hash line for config/rbac.yaml (PBKDF2-SHA256).

Usage:
  python scripts/hash_password.py
  python scripts/hash_password.py 'your-secret'

If no argument is given, reads password from stdin (no echo requires getpass).
"""
from __future__ import annotations

import getpass
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
from utils.password_hashing import hash_password  # noqa: E402


def main() -> None:
    if len(sys.argv) > 1:
        secret = sys.argv[1]
    else:
        secret = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm:  ")
        if secret != confirm:
            print("Passwords do not match.", file=sys.stderr)
            sys.exit(1)
    if not secret:
        print("Empty password.", file=sys.stderr)
        sys.exit(1)
    h = hash_password(secret)
    print("Add under the user in config/rbac.yaml:")
    print(f'  password_hash: "{h}"')


if __name__ == "__main__":
    main()
