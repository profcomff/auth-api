## Что нужно для запуска 

1. python3.11. Установка описана [тут](https://www.python.org/downloads/)

2. Docker. Как установить docker описано [тут](https://docs.docker.com/engine/install/)

3. PostgreSQL. Запустить команду
```console
docker run -d -p 5432:5432 -e POSTGRES_HOST_AUTH_METHOD=trust --name db-auth_api postgres:15
```

4. Опционально Kafka Cluster(если планиурется запускать userdata worker). Запуск описан [тут](https://github.com/profcomff/db-kafka)

## Как подготовиться к локальной разработке
1. Откройте консоль
2. Перейдите в папку с проектами
3. `git clone https://github.com/profcomff/auth-api.git`
4. Если у вас нет docker, то качайте его: https://www.docker.com/products/docker-desktop/
5. Выполните `docker run -d -p 5432:5432 -e POSTGRES_HOST_AUTH_METHOD=trust --name db-auth_api postgres:15`
6. Зайдите в проект
7. Создайте виртуальные окружение: https://docs.python.org/3/library/venv.html
8. Активируйте виртуальное окружение: https://docs.python.org/3/library/venv.html
9. pip install -r requirements.txt requirements.dev.txt
10. `DB_DSN=postgresql://postgres@localhost:5432/postgres alembic upgrade head`
11. Заполните .env файл. Для каждого из методов авторизации есть свои параметры в .env файле, если вам не нужен какой то из методов, его параметры могут быть none. Вставьте туда DB_DSN=postgresql://postgres@localhost:5432/postgres
12. `python3 -m pytest --verbosity=2 --showlocals --log-level=DEBUG` - должны все пройти
13. Запуск проекта производится командой `python -m auth_backend start`

##  Как запустить контейнер локально
0. Поставьте docker
1. Скачайте актуальный образ: docker pull ghcr.io/profcomff/auth-api:test
2.
```
docker run \
            --detach \
            -p 80:80 \
            --env DB_DSN='postgresql://...' \
            --env APPLICATION_HOST='https://localhost' \
            --env LKMSU_TEMPTOKEN='123' \
            --name "auth-api" \
            ghcr.io/profcomff/auth-api:test
```
3. Вы великолепны

## Как пользоваться(создать рута) CLI без докера
1. Создайте юзера `python -m auth_backend user create --email <email> --password <password>`
2. Создайте скоупы, которые вам надо(минимум это auth.scope.create, auth.group.create, auth.group.patch, auth.user.patch) `python -m auth_backend scope create --name <email> --creator <user_id(придет в ответе после создания юзера)>, --comment <comment>` - выполнить команду придется несколько раз
3. Создайте группу root `python -m auth_backend group create --name root --scopes <scopes>`
Пример: `python -m auth_backend group create --name root --scopes 1 2 3 4`
4. Добавьте рут юзера в рут группу `python -m auth_backend user_group create --user_id <user_id(придет в ответе после создания юзера)> --group_id <group_id(придет в ответе после создания группы)>`
5. Все, можно дальше создавать от имени рута все, что вы хотите


## Как пользоваться(создать рута) CLI в докере
1. Зайдите на сервер
2. `docker exec -it com_profcomff_auth_api_test bash` или `docker exec -it com_profcomff_auth_api bash`
3. Создайте юзера `python -m auth_backend user create --email <email> --password <password>`
4. Создайте скоупы, которые вам надо(минимум это auth.scope.create, auth.group.create, auth.group.patch, auth.user.patch) `python -m auth_backend scope create --name <email> --creator <user_id(придет в ответе после создания юзера)>, --comment <comment>` - выполнить команду придется несколько раз
5. Создайте группу root `python -m auth_backend group create --name root --scopes <scopes>`
Пример: `python -m auth_backend group create --name root --scopes 1 2 3 4`
6. Добавьте рут юзера в рут группу `python -m auth_backend user_group create --user_id <user_id(придет в ответе после создания юзера)> --group_id <group_id(придет в ответе после создания группы)>`
7. Все, можно дальше создавать от имени рута все, что вы хотите


## Как сделать, чтоб методы аутентификации не 500тили
1. Для каждого из методов аутентификации есть свои ключи

Вот их описание
---

## ENV-file description

- `DB_DSN` – Адрес базы данных в фаормате `postgresql://admin:admin@localhost:5432/dev`
- `EMAIL` – Адрес электронной почты (логин для входа) для отправки уведомлений по Email
- `EMAIL_PASS` – Пароль от электронной почты
- `HOST` – Хост для использования в шаблонах сообщений электронной почты

### Google
- `GOOGLE_REDIRECT_URL: str` – URL адрес страницы для получения данных авторизации на нашем фронтэнде
- `GOOGLE_SCOPES: list[str]` – Запрашиваемые у гугла права на управление аккаунтом, по умолчанию запрашивает данные пользователя
- `GOOGLE_CREDENTIALS: Json` – Данные приложения Google, получить можно в Google Cloud Console

### Physics
- `PHYSICS_REDIRECT_URL: str` – см. секцию *Google*
- `PHYSICS_SCOPES: list[str]` – см. секцию *Google*
- `PHYSICS_CREDENTIALS: Json` – см. секцию *Google*

### LK MSU
- `LKMSU_REDIRECT_URL` – URL адрес страницы для получения данных авторизации на нашем фронтэнде

### Yandex
- `YANDEX_REDIRECT_URL` – URL адрес страницы для получения данных авторизации на нашем фронтэнде
- `YANDEX_CLIENT_ID` - ID приложения, созданного в Яндексе
- `YANDEX_CLIENT_SECRET` - Ключ для получения токена пользователя в Яндексе

### MYMSU
- `MYMSU_REDIRECT_URL` – см. секцию *Yandex*
- `MYMSU_CLIENT_ID` - см. секцию *Yandex*
- `MYMSU_CLIENT_SECRET` - см. секцию *Yandex*

### Telegram
- `TELEGRAM_REDIRECT_URL` – URL адрес страницы для получения данных авторизации на нашем фронтэнде
- `TELEGRAM_BOT_TOKEN` - Токен бота приложения
---
Чтобы получить ключи, вам надо регистрировать приложения в облаках этих ресурсов
https://yandex.ru/dev/id/doc/ru/register-client

https://core.telegram.org/bots#3-how-do-i-create-a-bot

https://dev.vk.com/api/access-token/getting-started

https://console.cloud.google.com/welcome?project=design-school-api

##  Где взять готовые либы аутентификации
https://pypi.org/project/auth-lib-profcomff/

## Какие переменные нужны для запуска
- `DB_DSN=postgresql://postgres@localhost:5432/postgres`

### Опционально, если нужно запустить Kafka Worker
- `KAFKA_DSN=loacalhost:9092`

- `KAFKA_TOPICS='["dev-user-login"]'`

## Codestyle

- Black. Как пользоваться описано [тут](https://black.readthedocs.io/en/stable/)

- Также применяем [isort](https://pycqa.github.io/isort/)

