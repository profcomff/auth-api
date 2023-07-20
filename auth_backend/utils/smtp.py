import datetime
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum

from fastapi.background import BackgroundTasks
from retrying import retry
from sqlalchemy.orm import Session as DbSession

from auth_backend.exceptions import TooManyEmailRequests
from auth_backend.models.db import UserMessageDelay
from auth_backend.settings import Settings, get_settings


logger = logging.getLogger(__name__)


class ActionType(str, Enum):
    EMAIL_CONFIRMED = "email_confirmed"
    REGISTRATION = "regitration"
    PASSWORD_RESET = "password_reset"


class EmailDelay:
    settings: Settings = get_settings()

    @classmethod
    def create_user_delay(cls, ip: str, email: str, dbsession: DbSession):
        '''Create database entry'''
        cls.check_ip_delay(ip, dbsession)
        cls.check_email_delay(email, dbsession)
        user_delay = UserMessageDelay(user_ip=ip, user_email=email, delay_time=datetime.datetime.utcnow())
        dbsession.add(user_delay)
        dbsession.commit()

    @classmethod
    def delete_user_delay(cls, ip: str, email: str, dbsession: DbSession):
        """Delete database entries without delay"""
        time_filter = datetime.datetime.utcnow() - cls.settings.EMAIL_DELAY_TIME_IN_MINUTES * datetime.timedelta(
            minutes=1
        )
        if ip:
            dbsession.query(UserMessageDelay).filter(
                UserMessageDelay.user_ip == ip, UserMessageDelay.delay_time < time_filter
            ).delete()
        if email:
            dbsession.query(UserMessageDelay).filter(
                UserMessageDelay.user_email == email, UserMessageDelay.delay_time < time_filter
            ).delete()
        dbsession.commit()

    @classmethod
    def check_ip_delay(cls, ip: str, dbsession: DbSession):
        '''Check count of requests per unit of time by ip'''
        cls.delete_user_delay(email=None, ip=ip, dbsession=dbsession)
        time_filter = datetime.datetime.utcnow() - cls.settings.IP_DELAY_TIME_IN_MINUTES * datetime.timedelta(minutes=1)
        ip_list = (
            dbsession.query(UserMessageDelay)
            .filter(UserMessageDelay.user_ip == ip, UserMessageDelay.delay_time > time_filter)
            .all()
        )
        if len(ip_list) >= cls.settings.IP_DELAY_COUNT:
            time_delay = cls.settings.EMAIL_DELAY_TIME_IN_MINUTES * datetime.timedelta(minutes=1) - (
                datetime.datetime.utcnow() - min(list(i.delay_time for i in ip_list))
            )
            raise TooManyEmailRequests(time_delay)

    @classmethod
    def check_email_delay(cls, email: str, dbsession: DbSession):
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
        if len(email_list) >= cls.settings.EMAIL_DELAY_COUNT:
            time_delay = cls.settings.EMAIL_DELAY_TIME_IN_MINUTES * datetime.timedelta(minutes=1) - (
                datetime.datetime.utcnow() - min(list(i.delay_time for i in email_list))
            )
            raise TooManyEmailRequests(time_delay)

    @classmethod
    def delay(cls, ip: str, email: str, dbsession: DbSession):
        cls.check_ip_delay(ip, dbsession)
        cls.check_email_delay(email, dbsession)
        cls.create_user_delay(ip, email, dbsession)


class SendEmailMessage:
    settings: Settings = get_settings()
    from_email: str = settings.EMAIL

    @classmethod
    @retry(
        stop_max_attempt_number=settings.MAX_RETRIES,
        stop_max_delay=settings.STOP_MAX_DELAY,
        wait_random_min=settings.WAIT_MIN,
        wait_random_max=settings.WAIT_MAX,
        retry_on_exception=lambda exc: isinstance(exc, smtplib.SMTPException),
    )
    def email_task(cls, to_email: str, file_name: str, subject: str, **kwargs):
        with open(f"auth_backend/templates/{file_name}") as f:
            tmp = f.read()
            for key, value in kwargs.items():
                if f'{{{{{key}}}}}' in tmp:
                    tmp = tmp.replace(f'{{{{{key}}}}}', value)

        message = MIMEMultipart('related')
        message['Subject'] = subject
        message['From'] = cls.from_email
        message['To'] = to_email

        msgAlternative = MIMEMultipart('alternative')
        message.attach(msgAlternative)

        text = MIMEText(tmp, "html")
        msgAlternative.attach(text)

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
    def send(
        cls,
        to_email: str,
        ip: str,
        message_file_name: str,
        subject: str,
        dbsession: DbSession,
        background_tasks: BackgroundTasks,
        **kwargs,
    ):
        EmailDelay.delay(ip, to_email, dbsession)
        background_tasks.add_task(cls.email_task, to_email, message_file_name, subject, **kwargs)
