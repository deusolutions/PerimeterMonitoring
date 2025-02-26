import logging

logger = logging.getLogger(__name__)

class NotificationManager:
    def __init__(self):
        pass

    def send_notification(self, title: str, message: str, priority: str = "normal"):
        logger.info(f"Уведомление [{priority}]: {title} - {message}")