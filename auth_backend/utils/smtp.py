import asyncio
import datetime
import logging
import smtplib
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from fastapi.background import BackgroundTasks
from fastapi_sqlalchemy import db
from retrying import retry
from sqlalchemy.orm import Session as DbSession

from auth_backend.exceptions import TooManyEmailRequests
from auth_backend.models.db import UserMessageDelay
from auth_backend.settings import Settings, get_settings


logger = logging.getLogger(__name__)


class EmailDelay:
    settings: Settings = get_settings()

    @classmethod
    def create_user_delay(cls, ip, email, dbsession: DbSession):
        '''Create database entry'''
        cls.check_ip_delay(ip, dbsession)
        cls.check_email_delay(email, dbsession)
        entry_id = 0
        if dbsession.query(UserMessageDelay).all():
            entry_id = max(list(i.id for i in dbsession.query(UserMessageDelay).all())) + 1
        user_delay = UserMessageDelay(id=entry_id, user_ip=ip, user_email=email, delay_time=datetime.datetime.utcnow())
        dbsession.add(user_delay)
        dbsession.commit()

    @classmethod
    def delete_user_delay(cls, ip: None, email: None, dbsession: DbSession):
        """Delete database entries without delay"""
        time_filter = datetime.datetime.utcnow() - cls.settings.EMAIL_DELAY_TIME_IN_MINUTES * datetime.timedelta(
            minutes=1
        )
        if ip:
            dbsession.query(UserMessageDelay).filter(
                UserMessageDelay.user_ip == ip, UserMessageDelay.delay_time <= time_filter
            ).delete()
        if email:
            dbsession.query(UserMessageDelay).filter(
                UserMessageDelay.user_email == email, UserMessageDelay.delay_time <= time_filter
            ).delete()
        dbsession.commit()

    @classmethod
    def check_ip_delay(cls, ip, dbsession: DbSession):
        '''Check count of requests per unit of time by ip'''
        cls.delete_user_delay(email=None, ip=ip, dbsession=dbsession)
        time_filter = datetime.datetime.utcnow() - cls.settings.IP_DELAY_TIME_IN_MINUTES * datetime.timedelta(minutes=1)
        ip_list = (
            dbsession.query(UserMessageDelay)
            .filter(UserMessageDelay.user_ip == ip, UserMessageDelay.delay_time > time_filter)
            .all()
        )
        if len(ip_list) > cls.settings.IP_DELAY_COUNT:
            time_delay = cls.settings.EMAIL_DELAY_TIME_IN_MINUTES * datetime.timedelta(minutes=1) - (
                datetime.datetime.utcnow() - min(list(i.delay_time for i in ip_list))
            )
            raise TooManyEmailRequests(time_delay)

    @classmethod
    def check_email_delay(cls, email, dbsession: DbSession):
        '''Check count of requests per unit of time by email'''
        cls.delete_user_delay(email=email, ip=None, dbsession=dbsession)
        time_filter = datetime.datetime.utcnow() - cls.settings.EMAIL_DELAY_TIME_IN_MINUTES * datetime.timedelta(
            minutes=1
        )
        email_list = (
            dbsession.query(UserMessageDelay)
            .filter(UserMessageDelay.user_email == email, UserMessageDelay.delay_time > time_filter)
            .all()
        )
        if len(email_list) > cls.settings.EMAIL_DELAY_COUNT:
            time_delay = cls.settings.EMAIL_DELAY_TIME_IN_MINUTES * datetime.timedelta(minutes=1) - (
                datetime.datetime.utcnow() - min(list(i.delay_time for i in email_list))
            )
            raise TooManyEmailRequests(time_delay)

    @classmethod
    def delay(cls, ip, email, dbsession: DbSession):
        cls.create_user_delay(ip, email, dbsession)
        cls.check_ip_delay(ip, dbsession)
        cls.check_email_delay(email, dbsession)


class SendEmailMessage:
    settings: Settings = get_settings()
    from_email: str = None

    @classmethod
    @retry(
        stop_max_attempt_number=settings.MAX_RETRIES,
        stop_max_delay=settings.STOP_MAX_DELAY,
        wait_random_min=settings.WAIT_MIN,
        wait_random_max=settings.WAIT_MAX,
        retry_on_exception=lambda exc: isinstance(exc, smtplib.SMTPException),
    )
    def create_backtask_send_email(cls, to_email, file_name, subject, *, link=None):
        with open(f"auth_backend/templates/{file_name}") as f:  # main_confirmation
            tmp = f.read()
            if link and "{{url}}" in tmp:
                tmp = tmp.replace("{{url}}", link)

        with open("auth_backend/templates/image.png", 'rb') as f:
            img = MIMEImage(f.read(), name="image.png")

        message = MIMEMultipart('related')
        message['Subject'] = subject  # "Подтверждение регистрации Твой ФФ!"
        message['From'] = cls.from_email
        message['To'] = to_email

        msgAlternative = MIMEMultipart('alternative')
        message.attach(msgAlternative)

        text = MIMEText(tmp, "html")
        msgAlternative.attach(text)
        img.add_header('Content-ID', '<header>')
        message.attach(img)

        with smtplib.SMTP_SSL(cls.settings.SMTP_HOST, 465) as smtp:
            smtp.login(cls.settings.EMAIL, cls.settings.EMAIL_PASS)
            smtp.sendmail(cls.settings.EMAIL, to_email, message.as_string())

    @classmethod
    @retry(
        stop_max_attempt_number=settings.MAX_RETRIES,
        stop_max_delay=settings.STOP_MAX_DELAY,
        wait_random_min=settings.WAIT_MIN,
        wait_random_max=settings.WAIT_MAX,
        retry_on_exception=lambda exc: isinstance(exc, smtplib.SMTPException),
    )
    def send_email(
        cls,
        to_email,
        ip,
        message_file_name,
        subject,
        dbsession: DbSession,
        background_tasks: BackgroundTasks,
        *,
        link=None,
    ):
        EmailDelay.create_user_delay(ip, to_email, dbsession)
        EmailDelay.check_ip_delay(ip, dbsession)
        EmailDelay.check_email_delay(to_email, dbsession)
        background_tasks.add_task(
            cls.create_backtask_send_email,
            to_email=to_email,
            link=link,
            file_name=message_file_name,
            subject=subject,
        )
