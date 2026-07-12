.PHONY: setup test backend frontend verify
setup:
	python3.11 -m venv .venv
	.venv/bin/python -m pip install -U pip
	.venv/bin/pip install -r backend/requirements.txt
	cd frontend && npm install

test:
	PYTHONPATH=backend .venv/bin/pytest -q
	cd frontend && npm run build

backend:
	.venv/bin/uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8011

frontend:
	cd frontend && npm run dev -- --host 127.0.0.1 --port 5173

verify:
	python scripts/verify.py

deploy:
	bash scripts/deploy.sh
