run:
	source ./venv/bin/activate && uvicorn --reload --log-level debug auth_backend.routes.base:app

db:
	docker run -d -p 5432:5432 -e POSTGRES_HOST_AUTH_METHOD=trust --name db-auth_api postgres:15

migrate: db
	alembic upgrade head
