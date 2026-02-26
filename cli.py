#!/usr/bin/env python3
"""Repository-root CLI entrypoint.

README 예시(`python -m cli`)와 src 레이아웃을 호환시키는 프록시 래퍼.
"""

from src import cli as _impl

parse_args = _impl.parse_args


def main() -> int:
    """src.cli.main을 호출하되, parse_args monkeypatch를 프록시한다."""
    original_parse_args = _impl.parse_args
    _impl.parse_args = parse_args
    try:
        return _impl.main()
    finally:
        _impl.parse_args = original_parse_args


if __name__ == "__main__":
    raise SystemExit(main())
