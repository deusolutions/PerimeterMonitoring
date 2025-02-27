# modules/website_monitor.py
import logging
from typing import List, Dict, Any
import time
import requests
import config

logger = logging.getLogger(__name__)

class WebsiteMonitor:
    def __init__(self, db, notifier):
        self.db = db
        self.notifier = notifier
        self.websites = config.WEBSITES
        self.timeout = config.WEBSITE_TIMEOUT
        self.alert_status_codes = config.HTTP_STATUS_ALERT

    def _check_website(self, url: str) -> Dict[str, Any]:
        state = {
            "url": url,
            "is_up": False,
            "status_code": None,
            "response_time": None,
            "check_time": time.time()
        }
        try:
            start_time = time.time()
            response = requests.get(url, timeout=self.timeout)
            state["is_up"] = response.status_code in (200, 301, 302)
            state["status_code"] = response.status_code
            state["response_time"] = (time.time() - start_time) * 1000  # В миллисекундах
        except Exception as e:
            state["is_up"] = False
            state["status_code"] = None
            state["response_time"] = None
            logger.error(f"Ошибка при проверке сайта {url}: {str(e)}")
            self.notifier.send_notification(
                f"🔴 Сайт {url} недоступен",
                f"Сайт {url} перестал отвечать.\nОшибка: {str(e)}",
                priority="high"
            )
        return state

    def _detect_change(self, previous: Dict[str, Any], current: Dict[str, Any]) -> bool:
        return previous.get("is_up") != current["is_up"]

    def _notify_change(self, url: str, current: Dict[str, Any]) -> None:
        previous = self.db.get_website_state(url)
        if previous.get("is_up", False) and not current["is_up"]:
            title = f"🔴 Сайт {url} недоступен"
            message = f"Сайт {url} перестал отвечать."
        elif not previous.get("is_up", True) and current["is_up"]:
            title = f"🟢 Сайт {url} снова доступен"
            message = f"Сайт {url} восстановил работу."
        else:
            return
        self.notifier.send_notification(title, message, priority="medium" if current["is_up"] else "high")

    def check_all(self, websites: List[str] = None) -> Dict[str, Any]:
        websites = websites or self.websites
        logger.info(f"Запуск проверки {len(websites)} веб-сайтов")
        down_count = 0
        changes = False
        for url in websites:
            current_state = self._check_website(url)
            previous_state = self.db.get_website_state(url)
            if not current_state["is_up"]:
                down_count += 1
            if previous_state and self._detect_change(previous_state, current_state):
                changes = True
                self._notify_change(url, current_state)
            try:
                self.db.save_website_state(current_state)  # Используем save_website_state вместо save_website_change
            except Exception as e:
                logger.error(f"Ошибка при сохранении состояния сайта {url}: {str(e)}")
        logger.info(f"Проверка веб-сайтов завершена. {down_count} сайтов недоступно. Обнаружено {int(changes)} изменений статуса.")
        return {"down_count": down_count, "changes": changes}