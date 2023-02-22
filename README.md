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

---

## Добавление метода аутентификации
1. Продумайте, какой путь должен совершить пользователь, чтобы войти в сервис с использованием вашего метода аутентификации
    - Все методы должны поддерживать минимум 2 варианта взаимодействия: регистрация нового пользователя (она же, добавление метода аутентификации существующему пользователю) и повторный вход.
    - Большинство внешних приложений (Google/Yandex/Telegram и др.) уже придумали все за вас и используют стандарт OAuth2 для авторизации внешних приложений, поэтому они очень похожи друг на друга и можно посомтреть примеры. Google авторизация уже реализована и можно почитать пути пользователя выше.

2. Определитесь, какие методы нужны для работы с вашим методом авторизации.
    - По умолчанию есть 2 API ручки: `/login` – вход (повторный), и `/register` – первичная регистрация/добавление нового метода авторизации
    - Для OAuth2 авторизации и аутентификации также обязательно определены ручки `/auth_url` и `/redirect_url` – возвращают URL, куда пользователя должен перенаправить наш фронтенд для ввода логина и пароля на внешнем ресурсе, и URL, куда внешнее приложение перенаправит результат входа, соответственно
    - Вы можете определить и свои методы, но помните, что их нужно также поддержать и на фронтенде приложения. Обязательно опишите пошагово (а лучше нарисуйте схему в Miro или draw.io), как будут рабоать ваши методы со стороны пользователя/фронтенда

3. Создайте новый файл в папке `auth_backend/auth_plugins`, создайте класс и отнаследуйте его 
    - для legacy аутентификации от https://github.com/profcomff/auth-api/blob/1ce51bd532bd6f57c0abe922c7dd1a809d030723/auth_backend/auth_plugins/auth_method.py#L37
    - для OAuth аутентификации от https://github.com/profcomff/auth-api/blob/1ce51bd532bd6f57c0abe922c7dd1a809d030723/auth_backend/auth_plugins/auth_method.py#L112

4. Задайте классу описание, `prefix` и `tags` https://github.com/profcomff/auth-api/blob/1ce51bd532bd6f57c0abe922c7dd1a809d030723/auth_backend/auth_plugins/google.py#L31-L34
    - `prefix` используется как отправная точка для ваших методов. Ручка логина для метода авторизации с премиксом `/myauth` будет `/myauth/login`
    - Описание и теги используются для документирования кода. Зачастую без них непонятно, что вообще происходит. Не пропускайте их.

5. Создайте основные методы
    - Помните, что все методы являются `@staticmethod` или `@classmethod`. То есть не принимают аргумент `self` (текущий объект), а принимают ничего или `cls` (текущий класс) соответственно
    - Ручки `/login` и `/register` имеют сигнатуры `async def _login(...)` и `async def _register(...)` соответственно
    - Ручка `/login` обязательно возвращает объект https://github.com/profcomff/auth-api/blob/1ce51bd532bd6f57c0abe922c7dd1a809d030723/auth_backend/models/db.py#L117
    - Ручки `/auth_url` и `/redirect_url` методов OAuth2 обязательно возвращают оъект https://github.com/profcomff/auth-api/blob/1ce51bd532bd6f57c0abe922c7dd1a809d030723/auth_backend/auth_plugins/auth_method.py#L115-L116
