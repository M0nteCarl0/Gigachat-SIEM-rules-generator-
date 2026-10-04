"""Точка входа: `python -m siggen ...` работает без установки пакета."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
