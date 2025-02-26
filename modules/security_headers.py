import logging
import requests
from datetime import datetime
from typing import Dict, List, Any, Optional

from core.database import Database
from core.notification import NotificationManager
import config
import time

logger = logging.getLogger("SecurityHeaders")

class SecurityHeadersChecker:
    def __init__(self, db: Database, notifier: NotificationManager, config):
        self.db = db
        self.notifier = notifier
        self.enabled = config.SECURITY_HEADERS_CHECK_ENABLED
        try:
            self.critical_headers = config.SECURITY_HEADERS
        except AttributeError:
            logger.error("Ошибка при загрузке критических заголовков")
            self.critical_headers = ['Strict-Transport-Security', 'X-XSS-Protection']
        self.timeout = config.SECURITY_HEADERS_TIMEOUT
        self.user_agent = config.SECURITY_HEADERS_USER_AGENT
        self.verify_ssl = config.SECURITY_HEADERS_VERIFY_SSL

    def check_all(self, urls: Optional[List[str]] = None) -> Dict[str, Any]:
        if not self.enabled:
            logger.info("Проверка заголовков безопасности отключена")
            return {"results": [], "issues": [], "changes": []}
        if urls is None:
            urls = config.WEBSITES
        results = []
        issues = []
        changes = []
        for url in urls:
            logger.info(f"Проверка заголовков безопасности для {url}")
            try:
                headers_data = self._check_headers(url)
                results.append(headers_data)
                previous = self.db.get_last_security_headers_check(url)
                if previous and self._detect_changes(previous, headers_data):
                    changes.append(headers_data)
                    self._notify_change(url, previous["headers"], headers_data["headers"])
                self.db.save_security_headers_check(headers_data)
                missing_headers = self._check_missing_headers(headers_data["headers"])
                if missing_headers:
                    issues.append({"url": url, "missing_headers": missing_headers})
                    self._notify_missing_headers(url, missing_headers)
            except Exception as e:
                logger.error(f"Ошибка при проверке заголовков для {url}: {str(e)}")
        return {"results": results, "issues": issues, "changes": changes}

    def _check_headers(self, url: str) -> Dict[str, Any]:
        headers = {
            "User-Agent": self.user_agent
        }
        response = requests.get(url, headers=headers, timeout=self.timeout, verify=self.verify_ssl)
        return {
            "url": url,
            "headers": dict(response.headers),
            "timestamp": time.time()
        }

    def _detect_changes(self, previous: Dict[str, Any], current: Dict[str, Any]) -> bool:
        return previous["headers"] != current["headers"]

    def _check_missing_headers(self, headers: Dict[str, str]) -> List[str]:
        return [h for h in self.critical_headers if h not in headers]

    def _notify_change(self, url: str, old_headers: Dict[str, str], new_headers: Dict[str, str]) -> None:
        title = f"ℹ️ Изменения в заголовках безопасности для {url}"
        message = f"Обнаружены изменения в заголовках для {url}:\n"
        for header in set(old_headers.keys()) | set(new_headers.keys()):
            old = old_headers.get(header, "отсутствует")
            new = new_headers.get(header, "отсутствует")
            if old != new:
                message += f"{header}: было '{old}', стало '{new}'\n"
        self.notifier.send_notification(title, message)

    def _notify_missing_headers(self, url: str, missing: List[str]) -> None:
        title = f"⚠️ Отсутствуют заголовки безопасности для {url}"
        message = f"Для {url} отсутствуют критические заголовки: {', '.join(missing)}"
        self.notifier.send_notification(title, message, priority="medium")