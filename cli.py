"""
cli.py
MailIntel Command-Line Interface entry point.
Delegates to the Typer app defined in cli.main.
"""
from __future__ import annotations

import sys
from cli.main import app

if __name__ == "__main__":
    app()
