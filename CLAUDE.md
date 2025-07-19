# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

- **Linting**: `poetry run ruff check .` (or `poetry run ruff check <filename>` for specific files)
- **Formatting**: `poetry run ruff format .` (or `poetry run ruff format <filename>` for specific files)
- **Type checking**: `poetry run mypy --strict .`
- **Testing**: `poetry run pytest`
- **Run the CLI**: `poetry run python -m base64_dns_parser <base64_dns_response>`

## Architecture

This is a Python utility for decoding base64-encoded DNS responses into JSON format. The codebase consists of:

- **Core parsing logic** (`base64_dns_parser/__init__.py`): Contains the DNS response decoding functions including:
  - `decode_dns_response()`: Main entry point that decodes base64 and parses the DNS structure
  - `parse_name()`: Handles DNS name parsing with compression pointer support
  - `parse_answer()`: Parses DNS answer records (A, CNAME, and generic types)

- **CLI interface** (`base64_dns_parser/__main__.py`): Command-line tool with optional `--expand` flag to output individual answers as separate JSON objects

- **Testing** (`tests/test_decoding.py`): Contains test with expected DNS response structure

The tool outputs structured JSON with DNS header information, question details, and parsed answer records. Uses Poetry for dependency management and packaging.