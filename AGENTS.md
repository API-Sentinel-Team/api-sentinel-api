# Repository Guidelines

## Project Structure & Module Organization

This repository contains an API security platform with a Python backend and a Vite React frontend.

- `server/` holds the FastAPI application. API routes live in `server/api/routers/`, shared domain logic in `server/modules/`, ORM models in `server/models/`, and startup configuration in `server/config.py`.
- `migrations/` contains Alembic database migrations.
- `tests/` contains pytest suites: `unit/`, `integration/`, `security/`, and `load/`.
- `tests-library/` stores YAML security test templates used by the backend.
- `api-sentinel-view-main/` contains the React/TypeScript UI, with source in `src/`, Playwright tests in `tests/e2e/`, and static assets in `public/`.
- `infra/` contains deployment and sensor examples for Terraform, Kubernetes, nginx, and scripts.

## Build, Test, and Development Commands

Backend:

- `pip install -r requirements.txt` installs Python dependencies.
- `uvicorn server.api.main:app --reload --host 0.0.0.0 --port 8000` runs the API locally.
- `alembic upgrade head` applies database migrations.
- `make test-unit`, `make test-integration`, `make test-security`, and `make test-all` run the main pytest layers.
- `docker compose up --build` starts FastAPI, Postgres, Redis, and Kafka.

Frontend, from `api-sentinel-view-main/`:

- `npm install` installs UI dependencies.
- `npm run dev` starts Vite.
- `npm run build` creates a production build.
- `npm run lint`, `npm test`, and `npm run test:e2e` run ESLint, Vitest, and Playwright.

## Coding Style & Naming Conventions

Use 4-space indentation for Python, type hints for new public functions, `snake_case` for modules/functions, and `PascalCase` for classes. Keep FastAPI routers thin and place reusable behavior under `server/modules/`.

For React, use TypeScript, functional components, `PascalCase` component files, and `camelCase` helpers. Follow the existing Tailwind/shadcn patterns and run `npm run lint` before UI PRs.

## Testing Guidelines

Add or update tests near the touched behavior. Backend tests should be named `test_*.py` and placed in the appropriate `tests/` subfolder. Prefer unit coverage for module logic and integration/security tests for API, auth, tenancy, ingestion, and migration behavior. UI unit tests live under `src/test/`; browser flows belong in `tests/e2e/`.

## Commit & Pull Request Guidelines

Recent history uses short, direct commit subjects such as `sensor fixed` and `engine enhanced`. Prefer clearer imperative subjects, for example `Fix sensor ingestion auth`. PRs should describe the change, list verification commands, link related issues, and include screenshots for visible UI changes.

## Security & Configuration Tips

Copy `.env.example` for local settings and do not commit secrets, local cookies, or generated database files. Keep production-like credentials out of `docker-compose.yml` changes unless they are placeholders.
