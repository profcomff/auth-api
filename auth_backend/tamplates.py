MAIL_CONFIRMATION_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <img class="header" style="width: 100%;" src=""
        alt="Авторизация ФизФак МГУ" />
    <div class="content" style="width: 80%; max-width: 800px; padding: 10px; margin: 0 auto; font: 1.3rem sans-serif;">
        <h1>Регистрация успешно пройдена!</h1>
        <p>Привет! Это команда программистов ФФ МГУ!</p>
        <p>Благодарим тебя за регистрацию. Теперь ты сможешь пользоваться всем функционалом!</p>
        <p>Для завершения регистрации пройди по ссылке: <a href={{url}}>{{url}}</a></p>
    </div>
</body>
</html>
"""