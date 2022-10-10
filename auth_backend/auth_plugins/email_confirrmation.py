import smtplib
from auth_backend.settings import get_settings
from auth_backend.tamplates import MAIL_CONFIRMATION_TEMPLATE

settings = get_settings()


def send_confirmation_email(subject, to_addr, link):
    """
    Send confirmation email
    """
    from_addr = 'profcom@physics.msu.ru'

    BODY = "\r\n".join((
        f"From: {from_addr}",
        f"To: {to_addr}",
        f"Subject: {subject}",
        "Content-Type: text/html; charset=utf-8;",
        "",
        MAIL_CONFIRMATION_TEMPLATE.replace('{{url}}', link)
    ))

    smtpObj = smtplib.SMTP('smtp.gmail.com', 587)
    smtpObj.starttls()
    smtpObj.login(from_addr, settings.EMAIL_PASS)
    smtpObj.sendmail(from_addr, [to_addr], BODY.encode('utf-8'))
    smtpObj.quit()
