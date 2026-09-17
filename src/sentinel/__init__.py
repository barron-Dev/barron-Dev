"""Compatibility namespace for the Sentinel -> Cyclothone package migration.

All implementation modules now live under the cyclothone package. This namespace
keeps existing internal imports loadable while the repository is migrated atomically.
"""
from pathlib import Path

__path__ = [str(Path(__file__).resolve().parent.parent / "cyclothone")]
