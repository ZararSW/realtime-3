#!/usr/bin/env python3
"""Thin entry-point shim so `python run.py <url>` keeps working after the
restructure. The real implementation lives in the ``scanner`` package
(:func:`scanner.cli.main`); installed users get the ``webscan`` console command.
"""
import sys
from pathlib import Path

# Ensure the repo root is importable when run directly from a source checkout.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from scanner.cli import main

if __name__ == "__main__":
    main()
