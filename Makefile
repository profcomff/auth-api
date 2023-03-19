run:
	source ./venv/bin/activate && uvicorn --reload --log-config logging_dev.conf auth_backend.routes.base:app

configure: venv
	source ./venv/bin/activate && pip install -r requirements.dev.txt -r requirements.txt

venv:
	python3.11 -m venv venv

format:
	source ./venv/bin/activate && autoflake -r --in-place --remove-all-unused-imports ./auth_backend
	source ./venv/bin/activate && isort ./auth_backend
	source ./venv/bin/activate && black ./auth_backend

db:
	docker run -d -p 5432:5432 -e POSTGRES_HOST_AUTH_METHOD=trust --name db-auth_api postgres:15

migrate:
	source ./venv/bin/activate && alembic upgrade head

test:
	source ./venv/bin/activate && python3 -m pytest --verbosity=2 --showlocals --log-level=DEBUG
