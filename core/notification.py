# core/notification.py
import logging
from telegram import Bot
import config
import asyncio

logger = logging.getLogger(__name__)

class NotificationManager:
    def __init__(self):
        self.telegram_bot = None
        self.chat_id = config.TELEGRAM_CHAT_ID
        if config.TELEGRAM_TOKEN:
            self.telegram_bot = Bot(token=config.TELEGRAM_TOKEN)

    async def _send_telegram_async(self, title: str, message: str):
        if self.telegram_bot and self.chat_id:
            try:
                await self.telegram_bot.send_message(chat_id=self.chat_id, text=f"{title}\n{message}")
                logger.info("Уведомление отправлено в Telegram")
            except Exception as e:
                logger.error(f"Ошибка отправки в Telegram: {str(e)}")

    def send_notification(self, title: str, message: str, priority: str = "normal"):
        logger.info(f"Уведомление [{priority}]: {title} - {message}")
        if self.telegram_bot and self.chat_id:
            # Используем asyncio.run для синхронного вызова в асинхронной среде
            asyncio.run(self._send_telegram_async(title, message))