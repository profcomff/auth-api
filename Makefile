run:
	source ./venv/bin/activate && uvicorn --reload --log-level debug auth_backend.routes.base:app

db:
	docker compose up -d

migrate:
	alembic upgrade head
