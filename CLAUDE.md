# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

- **Linting**: `uv run ruff check` (or `uv run ruff check <filename>` for specific files)
- **Formatting**: `uv run ruff format` (or `uv run ruff format <filename>` for specific files)
- **Type checking**: `uv run ty check`
- **Testing**: `uv run pytest`
- **Run the CLI**: `uv run python -m base64_dns_parser <base64_dns_response>`

## Architecture

This is a Python utility for decoding base64-encoded DNS responses into JSON format. The codebase consists of:

- **Core parsing logic** (`base64_dns_parser/__init__.py`): Contains the DNS response decoding functions including:
  - `decode_dns_response()`: Main entry point that decodes base64 and parses the DNS structure
  - `parse_name()`: Handles DNS name parsing with compression pointer support
  - `parse_answer()`: Parses DNS answer records (A, CNAME, and generic types)

- **CLI interface** (`base64_dns_parser/__main__.py`): Command-line tool with optional `--expand` flag to output individual answers as separate JSON objects

- **Testing** (`tests/test_decoding.py`): Contains test with expected DNS response structure

The tool outputs structured JSON with DNS header information, question details, and parsed answer records. Uses `uv` for dependency management and packaging.
