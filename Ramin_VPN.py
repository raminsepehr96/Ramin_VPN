#!/usr/bin/env python3
"""Ramin VPN launcher.

Run this file.  All application logic lives beside it in core.py and the
specialized modules.  Keeping the launcher tiny makes startup predictable and
makes it easy to move the whole Ramin VPN folder to another Android/Termux
installation.
"""
from core import main

if __name__ == "__main__":
    main()
