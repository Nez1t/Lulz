#!/usr/bin/env python3
"""Portable Lulz entry point; no installation required."""
import sys

if sys.version_info < (3, 11):
    raise SystemExit("Lulz requires Python 3.11 or newer.")

from lulz.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
