import smtplib
from auth_backend.settings import get_settings

settings = get_settings()


def send_confirmation_email(to_addr, link):
    from_addr = settings.EMAIL

    with open("auth_backend/templates/main_confirmation.html") as f:
        tmp = f.read()
        tmp = tmp.replace("{{url}}", link)

    BODY = "\r\n".join(
        (
            f"From: {from_addr}",
            f"To: {to_addr}",
            "Subject: Подтверждение регистрации Твой ФФ!",
            "Content-Type: text/html; charset=utf-8;",
            "",
            tmp,
        )
    )

    smtpObj = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)
    smtpObj.starttls()
    smtpObj.login(from_addr, settings.EMAIL_PASS)
    smtpObj.sendmail(from_addr, [to_addr], BODY.encode('utf-8'))
    smtpObj.quit()


def send_reset_email(to_addr, link):
    from_addr = settings.EMAIL

    with open("auth_backend/templates/mail_change_confirmation.html") as f:
        tmp = f.read()
        tmp = tmp.replace("{{url}}", link)

    BODY = "\r\n".join(
        (
            f"From: {from_addr}",
            f"To: {to_addr}",
            "Subject: Подтверждение смены почты Твой ФФ!",
            "Content-Type: text/html; charset=utf-8;",
            "",
            tmp,
        )
    )

    smtpObj = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)
    smtpObj.starttls()
    smtpObj.login(from_addr, settings.EMAIL_PASS)
    smtpObj.sendmail(from_addr, [to_addr], BODY.encode('utf-8'))
    smtpObj.quit()


def send_change_password_confirmation(to_addr, link):
    from_addr = settings.EMAIL

    with open("auth_backend/templates/password_change_confirmation.html") as f:
        tmp = f.read()
        tmp = tmp.replace("{{url}}", link)

    BODY = "\r\n".join(
        (
            f"From: {from_addr}",
            f"To: {to_addr}",
            "Subject: Изменение пароля Твой ФФ!",
            "Content-Type: text/html; charset=utf-8;",
            "",
            tmp,
        )
    )

    smtpObj = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)
    smtpObj.starttls()
    smtpObj.login(from_addr, settings.EMAIL_PASS)
    smtpObj.sendmail(from_addr, [to_addr], BODY.encode('utf-8'))
    smtpObj.quit()


def send_changes_password_notification(to_addr):
    from_addr = settings.EMAIL

    with open("auth_backend/templates/password_change_notification.html") as f:
        tmp = f.read()

    BODY = "\r\n".join(
        (
            f"From: {from_addr}",
            f"To: {to_addr}",
            "Subject: Изменение пароля Твой ФФ!",
            "Content-Type: text/html; charset=utf-8;",
            "",
            tmp,
        )
    )

    smtpObj = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)
    smtpObj.starttls()
    smtpObj.login(from_addr, settings.EMAIL_PASS)
    smtpObj.sendmail(from_addr, [to_addr], BODY.encode('utf-8'))
    smtpObj.quit()
