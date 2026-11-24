.PHONY: up platform down devdata evaluate evaluate-extended evaluate-independent fetch-stratus replay-stratus replay-stratus-extended thesis test
compose = docker compose -f deploy/compose/compose.yaml

up:
	$(compose) up --build -d --wait

platform:
	$(compose) -f deploy/compose/platform.yaml up --build -d --wait

down:
	$(compose) down

devdata:
	$(compose) exec -T console python -m app.devdata seed

evaluate:
	PYTHONPATH=backend uv run --locked python -m app.devdata evaluate

evaluate-extended:
	PYTHONPATH=backend uv run --locked python -m app.devdata evaluate --end-day 2026-11-07 --extended

evaluate-independent:
	PYTHONPATH=backend uv run --locked python -m app.independent_evaluation

fetch-stratus:
	sh scripts/fetch_stratus.sh

replay-stratus:
	PYTHONPATH=backend uv run --locked python -m app.stratus replay

replay-stratus-extended:
	PYTHONPATH=backend uv run --locked python -m app.stratus replay --rules config/detections/aws-sensitive-control-plane.yml --report reports/stratus-extended.md

thesis:
	PYTHONPATH=backend uv run --locked python scripts/thesis/table_3_8.py
	PYTHONPATH=backend uv run --locked python scripts/thesis/table_3_9.py
	PYTHONPATH=backend uv run --locked python scripts/thesis/sensitivity.py

test:
	uv run --locked ruff check backend scripts
	uv run --locked ruff format --check backend scripts
	uv run --locked mypy
	uv run --locked pytest -q
