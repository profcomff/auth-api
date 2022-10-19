FROM python:3.10
WORKDIR /app

COPY ./requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

ADD gunicorn_conf.py alembic.ini /app/
ADD migrations /app/migrations
ADD auth_backend /app/auth_backend

CMD [ "gunicorn", "-k", "uvicorn.workers.UvicornWorker", "-c", "/app/gunicorn_conf.py", "auth_backend.routes.base:app" ]
