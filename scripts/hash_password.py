#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass

from rampart.app.security.passwords import hash_password


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a RAMPART local admin password hash.")
    parser.add_argument("password", nargs="?", help="Password to hash. Prompts securely if omitted.")
    args = parser.parse_args()
    password = args.password or getpass.getpass("Password: ")
    print(hash_password(password))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
