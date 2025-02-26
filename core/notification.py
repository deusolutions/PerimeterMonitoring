"""
Модуль для отправки уведомлений
"""
import logging
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List, Optional
import datetime

import config

logger = logging.getLogger(__name__)

class NotificationManager:
    def __init__(self):
        pass

    def send_notification(self, title: str, message: str, priority: str = "normal"):
        logger.info(f"Уведомление [{priority}]: {title} - {message}")