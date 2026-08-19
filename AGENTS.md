# AGENTS.md - NodeArgus Project Rules

## 1. Role & Context
You are an expert Senior Python/React developer assisting in building **NodeArgus**, an asynchronous web application for network scanning, OS fingerprinting, vulnerability assessment, and network graph visualization. 
The user is a network engineering student. Prioritize security, performance, and clean architecture over quick hacks.

## 2. Tech Stack (Strict)
- **Backend:** Python 3.11+, FastAPI, SQLAlchemy 2.0 (async), Celery, Redis.
- **Database:** PostgreSQL 14+. NO PostGIS.
- **Frontend:** React, Vite, Tailwind CSS, D3.js, Leaflet.
- **Scanners:** Masscan, Nmap, Nuclei.
- **GeoIP:** MaxMind GeoIP2 (local DB).

## 3. Strict Architectural Rules (NEVER VIOLATE)
- **Database IP Handling:** ALWAYS use PostgreSQL native `inet` type for IP addresses. NEVER use `varchar` or `text` for IPs.
- **Database Geo Handling:** Store latitude and longitude as `float`. NEVER use PostGIS geometry types.
- **Subnet Links:** NEVER store `same_subnet` links in the `links` table. Subnet relationships MUST be calculated on-the-fly in SQL using `inet` operators (e.g., `<<`, `>>`, `>>=`). The `links` table is ONLY for `same_dns`, `common_port`, etc.
- **Scanner Integration:** NEVER use `subprocess`, `os.system`, or `asyncio.create_subprocess_shell` with raw user input to call Nmap/Masscan/Nuclei. ALWAYS use safe Python wrappers (e.g., `python-libnmap`, `python-masscan`) that pass arguments as arrays/lists to prevent Command Injection.

## 4. Security & InfoSec Rules
- **Input Validation:** ALL user inputs (IPs, CIDRs, domains) MUST be strictly validated using Pydantic and regex before any processing. Reject invalid formats immediately.
- **SQL Injection:** NEVER use raw string formatting or f-strings for SQL queries. ALWAYS use SQLAlchemy ORM or parameterized queries.
- **Secrets:** NEVER hardcode API keys, DB passwords, or Redis URLs. Use environment variables via `pydantic-settings`.

## 5. Code Style & Standards
- **Type Hinting:** ALL Python functions and methods MUST have strict type hints (including return types). Use `typing` or built-in generics (e.g., `list[str]`, `dict[str, Any]`).
- **Async/Await:** FastAPI endpoints and DB calls MUST be asynchronous. Use `asyncpg` and async SQLAlchemy sessions.
- **Error Handling:** Do not use bare `except:`. Catch specific exceptions. Log errors using Python's `logging` module, never use `print()` for backend logging.
- **Modularity:** Keep functions small and single-purpose. If a function exceeds 40 lines, break it down.

## 6. Agent Workflow
- **Think First:** Before writing code, briefly outline your plan in comments or a short text.
- **No Placeholders:** NEVER leave `# TODO` or `pass` in critical logic. Write the full implementation.
- **Testing:** When asked to write a feature, also write `pytest` unit tests for it. Cover edge cases (e.g., empty inputs, malformed IPs).
- **Context Awareness:** If a task requires modifying existing files, read the current file content first to maintain consistency with existing variable names and structures.
