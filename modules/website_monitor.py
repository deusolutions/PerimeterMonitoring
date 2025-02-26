import logging
import requests
from datetime import datetime
from typing import Dict, List, Any, Optional

import config
from core.database import Database
from core.notification import NotificationManager

logger = logging.getLogger("WebsiteMonitor")

class WebsiteMonitor:
    def __init__(self, db: Database, notifier: NotificationManager):
        self.db = db
        self.notifier = notifier
        self.websites = config.WEBSITES
        self.timeout = config.WEBSITE_TIMEOUT  # Используем WEBSITE_TIMEOUT из config.py
    
    def _check_website(self, url: str) -> Dict[str, Any]:
        try:
            response = requests.get(url, timeout=self.timeout, verify=True)
            response_time = int(response.elapsed.total_seconds() * 1000)
            return {
                "url": url,
                "is_up": True,
                "status_code": response.status_code,
                "response_time": response_time,
                "error": None,
                "check_time": datetime.now()
            }
        except requests.RequestException as e:
            return {
                "url": url,
                "is_up": False,
                "status_code": None,
                "response_time": None,
                "error": str(e),
                "check_time": datetime.now()
            }
    
    def check_all(self, urls: Optional[List[str]] = None) -> Dict[str, Any]:
        if urls is None:
            websites = self.websites
        else:
            websites = urls
        results = []
        down_count = 0
        changes = []
        logger.info(f"Запуск проверки {len(websites)} веб-сайтов")
        for url in websites:
            try:
                result = self._check_website(url)
                results.append(result)
                previous_state = self.db.get_website_state(url)
                if result["is_up"]:
                    if previous_state and not previous_state["is_up"]:
                        changes.append({
                            "url": url,
                            "old_state": previous_state,
                            "new_state": result,
                            "change_time": datetime.now()
                        })
                        self._notify_up(url)
                else:
                    down_count += 1
                    if previous_state and previous_state["is_up"]:
                        changes.append({
                            "url": url,
                            "old_state": previous_state,
                            "new_state": result,
                            "change_time": datetime.now()
                        })
                        self._notify_down(url, result["error"])
                self.db.save_website_state(result)
                if changes:
                    for change in changes:
                        self.db.save_website_change(change)
            except Exception as e:
                logger.error(f"Ошибка при проверке сайта {url}: {str(e)}")
        logger.info(f"Проверка веб-сайтов завершена. {down_count} сайтов недоступно. Обнаружено {len(changes)} изменений статуса.")
        return {
            "results": results,
            "down_count": down_count,
            "changes": changes
        }
    
    def _notify_down(self, url: str, error: str) -> None:
        title = f"🔴 Сайт {url} недоступен"
        message = f"Сайт {url} перестал отвечать.\nОшибка: {error}"
        self.notifier.send_notification(title, message, priority="high")
    
    def _notify_up(self, url: str) -> None:
        title = f"🟢 Сайт {url} снова доступен"
        message = f"Сайт {url} восстановил работу."
        self.notifier.send_notification(title, message, priority="medium")