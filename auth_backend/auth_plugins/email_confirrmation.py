import smtplib
from auth_backend.settings import get_settings
from auth_backend.tamplates import MAIL_CONFIRMATION_TEMPLATE

settings = get_settings()


def send_confirmation_email(subject, to_addr, link):
    """
    Send confirmation email
    """
    from_addr = settings.EMAIL

    with open("templates/mail_confirmation.html") as f:
        tmp = f.read()
        tmp = tmp.format(url=link)

    BODY = "\r\n".join(
        (
            f"From: {from_addr}",
            f"To: {to_addr}",
            f"Subject: {subject}",
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


def send_change_password_confirmation(subject, to_addr, link):
    """
    Send change password confirmation
    """
    from_addr = settings.EMAIL

    with open("templates/reset_password.html") as f:
        tmp = f.read()
        tmp = tmp.format(url=link)

    BODY = "\r\n".join(
        (
            f"From: {from_addr}",
            f"To: {to_addr}",
            f"Subject: {subject}",
            "Content-Type: text/html; charset=utf-8;",
            "",
            tmp
        )
    )

    smtpObj = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT)
    smtpObj.starttls()
    smtpObj.login(from_addr, settings.EMAIL_PASS)
    smtpObj.sendmail(from_addr, [to_addr], BODY.encode('utf-8'))
    smtpObj.quit()
