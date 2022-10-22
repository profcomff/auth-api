args := $(wordlist 2, 100, $(MAKECMDGOALS))
ifndef args
MESSAGE = "No such command (or you pass two or many targets to )."
else
MESSAGE = "Done"
endif

run:
	source ./venv/bin/activate && uvicorn --reload --log-level debug auth_backend.routes.base:app

db:
	docker compose up -d

migrate:
	alembic upgrade head

test:
	python3 -m pytest --verbosity=2 --showlocals --log-level=DEBUG

migrate: ##@Database Do all migrations in database
	alembic upgrade $(args)