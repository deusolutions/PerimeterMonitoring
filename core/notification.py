import logging
from telegram import Bot
import asyncio
import config

logger = logging.getLogger(__name__)

class NotificationManager:
    def __init__(self):
        self.telegram_bot = None
        self.chat_id = config.TELEGRAM_CHAT_ID
        if config.TELEGRAM_TOKEN:
            self.telegram_bot = Bot(token=config.TELEGRAM_TOKEN)

    def send_notification(self, title: str, message: str, priority: str = "normal"):
        """Отправляет уведомление в лог и Telegram (если настроен)."""
        logger.info(f"Уведомление [{priority}]: {title} - {message}")
        if self.telegram_bot and self.chat_id:
            try:
                # Используем asyncio для асинхронной отправки
                asyncio.run(self._send_telegram(title, message))
                logger.info("Уведомление отправлено в Telegram")
            except Exception as e:
                logger.error(f"Ошибка отправки в Telegram: {str(e)}")

    async def _send_telegram(self, title: str, message: str):
        """Асинхронная отправка сообщения в Telegram."""
        await self.telegram_bot.send_message(chat_id=self.chat_id, text=f"{title}\n{message}")