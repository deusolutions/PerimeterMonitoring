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

logger = logging.getLogger("NotificationManager")

class NotificationManager:
    """Класс для управления уведомлениями"""
    
    def __init__(self):
        self.email = config.NOTIFICATION_EMAIL
        self.smtp_server = config.SMTP_SERVER
        self.smtp_port = config.SMTP_PORT
        self.smtp_user = config.SMTP_USER
        self.smtp_password = config.SMTP_PASSWORD
        
        self.slack_webhook_url = config.SLACK_WEBHOOK_URL
        self.use_slack = config.USE_SLACK
    
    def send_notification(self, title: str, message: str, priority: str = "normal") -> bool:
        """
        Отправка уведомления через все настроенные каналы
        
        Args:
            title: Заголовок уведомления
            message: Текст уведомления
            priority: Приоритет уведомления ('low', 'normal', 'high')
            
        Returns:
            bool: True, если отправка успешна хотя бы через один канал
        """
        success = False
        
        # Отправка по электронной почте
        if self.email and self.smtp_server:
            email_success = self._send_email(title, message, priority)
            success = success or email_success
        
        # Отправка в Slack
        if self.use_slack and self.slack_webhook_url:
            slack_success = self._send_slack(title, message, priority)
            success = success or slack_success
        
        return success
    
    def _send_email(self, title: str, message: str, priority: str) -> bool:
        """
        Отправка уведомления по электронной почте
        
        Args:
            title: Заголовок уведомления
            message: Текст уведомления
            priority: Приоритет уведомления
            
        Returns:
            bool: True, если отправка успешна
        """
        try:
            # Создание сообщения
            msg = MIMEMultipart()
            msg['From'] = self.smtp_user
            msg['To'] = self.email
            msg['Subject'] = title
            
            # Добавление приоритета (X-Priority: 1-высокий, 3-нормальный, 5-низкий)
            priority_map = {'high': '1', 'normal': '3', 'low': '5'}
            msg['X-Priority'] = priority_map.get(priority, '3')
            
            # Добавление текста сообщения
            msg.attach(MIMEText(message, 'plain'))
            
            # Отправка сообщения
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            
            logger.info(f"Уведомление отправлено по email: {title}")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка при отправке email: {str(e)}")
            return False
    
    def _send_slack(self, title: str, message: str, priority: str) -> bool:
        """
        Отправка уведомления в Slack
        
        Args:
            title: Заголовок уведомления
            message: Текст уведомления
            priority: Приоритет уведомления
            
        Returns:
            bool: True, если отправка успешна
        """
        try:
            # Определение цвета в зависимости от приоритета
            color_map = {'high': 'danger', 'normal': 'good', 'low': '#439FE0'}
            color = color_map.get(priority, 'good')
            
            # Создание сообщения
            payload = {
                "attachments": [
                    {
                        "fallback": title,
                        "color": color,
                        "title": title,
                        "text": message,
                        "footer": "Security Perimeter Monitoring",
                        "ts": int(datetime.datetime.now().timestamp())
                    }
                ]
            }
            
            # Отправка сообщения
            response = requests.post(
                self.slack_webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                logger.info(f"Уведомление отправлено в Slack: {title}")
                return True
            else:
                logger.error(f"Ошибка при отправке в Slack: {response.status_code} {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Ошибка при отправке в Slack: {str(e)}")
            return False