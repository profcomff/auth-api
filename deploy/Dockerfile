FROM tiangolo/uvicorn-gunicorn-fastapi:python3.11
ARG APP_VERSION=v0.0.0-dev
ENV APP_VERSION=${APP_VERSION}
ENV APP_NAME=auth_backend
ENV APP_MODULE=${APP_NAME}.routes.base:app

# Копируем файлы зависимостей и устанавливаем их
COPY ./requirements.txt /app/
RUN pip install -U -r /app/requirements.txt

# Копируем сопуствующие файлы
COPY ./deploy/prestart.sh ./deploy/logging_dev.conf ./deploy/logging_test.conf ./deploy/logging_prod.conf ./migrations ./alembic.ini /app/

# Копируем сам проект
COPY ./${APP_NAME} /app/${APP_NAME}
