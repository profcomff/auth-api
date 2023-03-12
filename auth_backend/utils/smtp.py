import smtplib
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from retrying import retry

from auth_backend.settings import get_settings
from pydantic import EmailStr

settings = get_settings()


@retry(
    stop_max_attempt_number=settings.MAX_RETRIES,
    stop_max_delay=settings.STOP_MAX_DELAY,
    wait_random_min=settings.WAIT_MIN,
    wait_random_max=settings.WAIT_MAX,
    retry_on_exception=lambda exc: isinstance(exc, smtplib.SMTPException),
)
def send_confirmation_email(to_addr, link):
    from_addr = settings.EMAIL

    with open("auth_backend/templates/main_confirmation.html") as f:
        tmp = f.read()
        tmp = tmp.replace("{{url}}", link)

    with open("auth_backend/templates/image.png", 'rb') as f:
        img = MIMEImage(f.read(), name="image.png")

    message = MIMEMultipart('related')
    message['Subject'] = "Подтверждение регистрации Твой ФФ!"
    message['From'] = from_addr
    message['To'] = to_addr

    msgAlternative = MIMEMultipart('alternative')
    message.attach(msgAlternative)

    text = MIMEText(tmp, "html")
    msgAlternative.attach(text)
    img.add_header('Content-ID', '<header>')
    message.attach(img)

    with smtplib.SMTP_SSL(settings.SMTP_HOST, 465) as smtp:
        smtp.login(settings.EMAIL, settings.EMAIL_PASS)
        smtp.sendmail(settings.EMAIL, to_addr, message.as_string())


@retry(
    stop_max_attempt_number=settings.MAX_RETRIES,
    stop_max_delay=settings.STOP_MAX_DELAY,
    wait_random_min=settings.WAIT_MIN,
    wait_random_max=settings.WAIT_MAX,
    retry_on_exception=lambda exc: isinstance(exc, smtplib.SMTPException),
)
def send_reset_email(to_addr, link):
    from_addr = settings.EMAIL

    with open("auth_backend/templates/mail_change_confirmation.html") as f:
        tmp = f.read()
        tmp = tmp.replace("{{url}}", link)

    with open("auth_backend/templates/image.png", 'rb') as f:
        img = MIMEImage(f.read(), name="image.png")

    message = MIMEMultipart('related')
    message['Subject'] = "Смена почты Твой ФФ!"
    message['From'] = from_addr
    message['To'] = to_addr

    msgAlternative = MIMEMultipart('alternative')
    message.attach(msgAlternative)

    text = MIMEText(tmp, "html")
    msgAlternative.attach(text)
    img.add_header('Content-ID', '<header>')
    message.attach(img)

    with smtplib.SMTP_SSL(settings.SMTP_HOST, 465) as smtp:
        smtp.login(settings.EMAIL, settings.EMAIL_PASS)
        smtp.sendmail(settings.EMAIL, to_addr, message.as_string())


@retry(
    stop_max_attempt_number=settings.MAX_RETRIES,
    stop_max_delay=settings.STOP_MAX_DELAY,
    wait_random_min=settings.WAIT_MIN,
    wait_random_max=settings.WAIT_MAX,
    retry_on_exception=lambda exc: isinstance(exc, smtplib.SMTPException),
)
def send_change_password_confirmation(to_addr, link):
    from_addr = settings.EMAIL

    with open("auth_backend/templates/password_change_confirmation.html") as f:
        tmp = f.read()
        tmp = tmp.replace("{{url}}", link)

    with open("auth_backend/templates/image.png", 'rb') as f:
        img = MIMEImage(f.read(), name="image.png")

    message = MIMEMultipart('related')
    message['Subject'] = "Смена пароля Твой ФФ!"
    message['From'] = from_addr
    message['To'] = to_addr

    msgAlternative = MIMEMultipart('alternative')
    message.attach(msgAlternative)

    text = MIMEText(tmp, "html")
    msgAlternative.attach(text)
    img.add_header('Content-ID', '<header>')
    message.attach(img)

    with smtplib.SMTP_SSL(settings.SMTP_HOST, 465) as smtp:
        smtp.login(settings.EMAIL, settings.EMAIL_PASS)
        smtp.sendmail(settings.EMAIL, to_addr, message.as_string())


@retry(
    stop_max_attempt_number=settings.MAX_RETRIES,
    stop_max_delay=settings.STOP_MAX_DELAY,
    wait_random_min=settings.WAIT_MIN,
    wait_random_max=settings.WAIT_MAX,
    retry_on_exception=lambda exc: isinstance(exc, smtplib.SMTPException),
)
def send_changes_password_notification(to_addr):
    from_addr = settings.EMAIL

    with open("auth_backend/templates/password_change_notification.html") as f:
        tmp = f.read()

    with open("auth_backend/templates/image.png", 'rb') as f:
        img = MIMEImage(f.read(), name="image.png")

    message = MIMEMultipart('related')
    message['Subject'] = "Смена пароля Твой ФФ!"
    message['From'] = from_addr
    message['To'] = to_addr

    msgAlternative = MIMEMultipart('alternative')
    message.attach(msgAlternative)

    text = MIMEText(tmp, "html")
    msgAlternative.attach(text)
    img.add_header('Content-ID', '<header>')
    message.attach(img)

    with smtplib.SMTP_SSL(settings.SMTP_HOST, 465) as smtp:
        smtp.login(settings.EMAIL, settings.EMAIL_PASS)
        smtp.sendmail(settings.EMAIL, to_addr, message.as_string())
