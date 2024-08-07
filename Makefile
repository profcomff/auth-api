SHELL := /bin/bash

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
	source ./venv/bin/activate && autoflake -r --in-place --remove-all-unused-imports ./tests
	source ./venv/bin/activate && isort ./tests
	source ./venv/bin/activate && black ./tests
	source ./venv/bin/activate && autoflake -r --in-place --remove-all-unused-imports ./migrations
	source ./venv/bin/activate && isort ./migrations
	source ./venv/bin/activate && black ./migrations

db:
	docker run -d -p 5432:5432 -e POSTGRES_HOST_AUTH_METHOD=trust --name db-auth_api postgres:15


migrate:
	source ./venv/bin/activate && alembic upgrade head

test:
	source ./venv/bin/activate && python3 -m pytest --verbosity=2 --showlocals --log-level=DEBUG

create-user:
	python -m auth_backend user create --email test-user@profcomff.com --password string

create-admin:
	source ./venv/bin/activate && python -m auth_backend user create --email test-admin@profcomff.com --password string
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.group.create                     --comment auth.group.create                     --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.group.delete                     --comment auth.group.delete                     --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.group.read                       --comment auth.group.read                       --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.group.update                     --comment auth.group.update                     --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.scope.create                     --comment auth.scope.create                     --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.scope.delete                     --comment auth.scope.delete                     --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.scope.read                       --comment auth.scope.read                       --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.scope.update                     --comment auth.scope.update                     --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.user.delete                      --comment auth.user.delete                      --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.user.read                        --comment auth.user.read                        --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.user.update                      --comment auth.user.update                      --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.airflow_outer_auth.link.read     --comment auth.airflow_outer_auth.link.read     --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.airflow_outer_auth.link.create   --comment auth.airflow_outer_auth.link.create   --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.airflow_outer_auth.link.delete   --comment auth.airflow_outer_auth.link.delete   --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.coder_outer_auth.link.read       --comment auth.coder_outer_auth.link.read       --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.coder_outer_auth.link.create     --comment auth.coder_outer_auth.link.create     --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.coder_outer_auth.link.delete     --comment auth.coder_outer_auth.link.delete     --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.mailu_outer_auth.link.read       --comment auth.mailu_outer_auth.link.read       --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.mailu_outer_auth.link.create     --comment auth.mailu_outer_auth.link.create     --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.mailu_outer_auth.link.delete     --comment auth.mailu_outer_auth.link.delete     --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.postgres_outer_auth.link.read    --comment auth.postgres_outer_auth.link.read    --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.postgres_outer_auth.link.create  --comment auth.postgres_outer_auth.link.create  --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend scope create --name auth.postgres_outer_auth.link.delete  --comment auth.postgres_outer_auth.link.delete  --creator_email test-admin@profcomff.com
	source ./venv/bin/activate && python -m auth_backend user_group create --email test-admin@profcomff.com

login-user:
	curl -X 'POST' 'http://localhost:8000/email/login' -H 'accept: application/json' -H 'Content-Type: application/json' -d '{"email": "test-user@profcomff.com", "password": "string"}'

login-admin:
	curl -X 'POST' 'http://localhost:8000/email/login' -H 'accept: application/json' -H 'Content-Type: application/json' -d '{"email": "test-admin@profcomff.com", "password": "string"}'
