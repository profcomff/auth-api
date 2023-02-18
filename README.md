# auth-api
 API сервиса аутентификации и авторизации в приложение Твой ФФ!

## Запуск

1) Перейдите в папку проекта

2) Создайте виртуальное окружение командой и активируйте его:
```console
foo@bar:~$ python3 -m venv venv
foo@bar:~$ source ./venv/bin/activate  # На MacOS и Linux
foo@bar:~$ venv\Scripts\activate  # На Windows
```

3) Установите библиотеки
```console
foo@bar:~$ pip install -r requirements.txt
```
4) Запускайте приложение!
```console
foo@bar:~$ python -m auth_backend
```

---

## ENV-file description

DB_DSN=postgresql://admin:admin@localhost:5432/?
EMAIL_PASS=
EMAIL=
HOST=

### Google
`GOOGLE_REDIRECT_URL: str` – URL адрес страницы для получения данных авторизации на нашем фронтэнде
`GOOGLE_SCOPES: list[str]` – Запрашиваемые у гугла права на управление аккаунтом, по умолчанию запрашивает данные пользователя
`GOOGLE_CREDENTIALS: Json` – Данные приложения Google, получить можно в Google Cloud Console

### Physics
`PHYSICS_REDIRECT_URL: str` – см. секцию *Google*
`PHYSICS_SCOPES: list[str]` – см. секцию *Google*
`PHYSICS_CREDENTIALS: Json` – см. секцию *Google*

### LK MSU
`LKMSU_REDIRECT_URL` – URL адрес страницы для получения данных авторизации на нашем фронтэнде

---

## Сценарий использования
### Email: регистрация нового аккаунта
1. Дернуть ручку `POST /email/registrate` . Вы передаете `{email: "", password: ""}`
2. На почту приходит письмо с линком на `GET /email/approve?token='...'`, если по ней перейти то почта будет подтверждена и регистрацию можно считать завершенной.

### Email: вход в аккаунт
1. Дернуть ручку `POST /email/login`. там всего один вариант логина, никуда не денетесь
2. Вам придет токен, сохраняйте его кууда нибудь, срок действия ограничен.

### Email: Восстановление забытого пароля
1. Дернуть ручку `POST /email/reset/password/request`. Вы передаете `{email: ""}`в нагрузке
2. Вам придет письмо, где будет ссылка НА ФРОНТ(надо сделать это), в ссылке будет reset_token
3. Токен надо передать в ручку `POST /email/reset/password` в заголовках, вместе с `{email: "", new_password: ""}` и пароль будет изменен. email не понадобится после решения #36

### Email: Изменение пароля
1. Если пароль не забыт, а просто надо его поменять. Тогда в `POST /email/reset/password/request` передается токен авторизации, в теле вы передаете `{email: "", password: "", new_password: ""}`
2. Отправляете запрос и всё, пароль изменен, вам придет письмо с уведомлением о смене пароляю

### Email: Изменение адреса электронной почты
1. Дернуть ручку `POST /email/reset/email/request`. Всего один вариант, передаете новое мыло в теле `{email: ""}` и токен атворизации в заголовках
2. На почту придет письмо с подтверждением почты, там будет токен подтверждения в query параметрах. Ссылка ведет на ручку GET пока что, но надо переделать, чтобы тоже вела на фронт.

### Google/Physics: вход пользователя с аккаунтом Google
*Все примеры написаны для Google аккаунта, для аккаунта physics.msu.ru средует делать запросы к `/physics-msu` вместо `/google`*

1. Получаем адрес для запроса на сервер Google: `GET /google/auth_url`
2. Редиректим пользователя на этот url, пользователь входит в аккаунт и возвращается на страницу, которую можно узнать запросом `GET /google/redirect_url`
3. Если Google не передал в ответе GET параметр `error`, передаем GET параметры страницы на сервер авториации в теле POST запроса в формате JSON: `POST /google/login`. Иначе возвращаем ошибку авторизации
4. При успешном входе получаем `token` сессии. Если сервер авторизации ответил ошибкой 401:
   1. запоминаем значение id_token из ответа.
   2. Предлагаем пользователю завести новый аккаунт нашего приложения, связанный с гуглом
5. Если пользователь соглашается, делаем запрос с `{"id_token": "<id-token>"}` в теле на адрес `POST /google/register`. При успешном входе получаем `token` сессии, иначе показываем экран ошибки авторизации

### Google/Physics: добавление аккаунта Google как второго метода входа
*Все примеры написаны для Google аккаунта, для аккаунта physics.msu.ru средует делать запросы к `/physics-msu` вместо `/google`*

1. Получаем адрес для запроса на сервер Google: `GET /google/auth_url`
2. Редиректим пользователя на этот url, пользователь входит в аккаунт и возвращается на страницу, которую можно узнать запросом `GET /google/redirect_url`
3. Если Google не передал в ответе GET параметр `error`, передаем данные на сервер авториации: `POST /google/register`, указываем заголовок `Authorization: <auth-token>`. Иначе возвращаем ошибку авторизации
4. При успешном входе получаем `token` сессии, иначе показываем экран ошибки авторизации
