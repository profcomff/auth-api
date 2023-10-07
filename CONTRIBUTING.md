## Что нужно для запуска 

1. python3.11. Установка описана [тут](https://www.python.org/downloads/)

2. Docker. Как установить docker описано [тут](https://docs.docker.com/engine/install/)

3. PostgreSQL. Запустить команду
```console
docker run -d -p 5432:5432 -e POSTGRES_HOST_AUTH_METHOD=trust --name db-auth_api postgres:15
```

4. Опционально Kafka Cluster(если планиурется запускать userdata worker). Запуск описан [тут](https://github.com/profcomff/db-kafka)

## Перед разработкой стоит почитать
- Гайд по разработке Auth API. Он вынесен в [wiki](https://github.com/profcomff/.github/wiki/Сервис-авторизации)

## Какие переменные нужны для запуска
- `DB_DSN=postgresql://postgres@localhost:5432/postgres`

### Опционально, если нужно запустить Kafka Worker
- `KAFKA_DSN=loacalhost:9092`

- `KAFKA_TOPICS='["dev-user-login"]'`

### Если надо тестировать методы авторизации
-  Процесс получения ключей и их описание есть в README и [тут](https://github.com/profcomff/.github/wiki/Сервис-авторизации)


## Codestyle

- Black. Как пользоваться описано [тут](https://black.readthedocs.io/en/stable/)

- Также применяем [isort](https://pycqa.github.io/isort/)

