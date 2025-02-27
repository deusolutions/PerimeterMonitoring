# modules/security_headers.py
import logging
import requests
from typing import List, Dict, Any
import time
import config

logger = logging.getLogger("SecurityHeaders")

class SecurityHeadersChecker:
    def __init__(self, db, notifier, config_obj):
        self.db = db
        self.notifier = notifier
        self.enabled = config.SECURITY_HEADERS_CHECK_ENABLED
        self.headers = config.SECURITY_HEADERS
        self.timeout = config.SECURITY_HEADERS_TIMEOUT
        self.user_agent = config.SECURITY_HEADERS_USER_AGENT
        self.verify_ssl = config.SECURITY_HEADERS_VERIFY_SSL

    def _check_headers(self, url: str) -> Dict[str, Any]:
        if not self.enabled:
            logger.info("Проверка заголовков безопасности отключена")
            return {"url": url, "headers": {}, "issues": [], "check_time": time.time()}
        logger.info(f"Проверка заголовков безопасности для {url}")
        headers_info = {"url": url, "headers": {}, "issues": [], "check_time": time.time()}
        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                headers={"User-Agent": self.user_agent},
                verify=self.verify_ssl
            )
            headers_info["headers"] = dict(response.headers)
            missing_headers = [h for h in self.headers if h not in response.headers]
            if missing_headers:
                headers_info["issues"] = missing_headers
                self.notifier.send_notification(
                    f"⚠️ Отсутствуют заголовки безопасности для {url}",
                    f"Для {url} отсутствуют критические заголовки: {', '.join(missing_headers)}",
                    priority="medium"
                )
        except Exception as e:
            logger.error(f"Ошибка при проверке заголовков для {url}: {str(e)}")
            headers_info["error"] = str(e)
        return headers_info

    def check_all(self, urls: List[str] = None) -> Dict[str, Any]:
        urls = urls or [r["url"] for r in self.db.get_all_records("security_headers")]
        logger.info(f"Проверка заголовков для {len(urls)} URL")
        issues = []
        changes = False
        for url in urls:
            current_headers = self._check_headers(url)
            previous_headers = self.db.get_security_headers(url)  # Заменили get_last_security_headers_check
            prev_dict = {h["header_name"]: h["header_value"] for h in previous_headers}
            curr_dict = current_headers["headers"]
            if prev_dict != curr_dict:
                changes = True
            if current_headers.get("issues"):
                issues.extend(current_headers["issues"])
            for header_name, header_value in current_headers["headers"].items():
                try:
                    self.db.save_security_headers({
                        "url": url,
                        "header_name": header_name,
                        "header_value": header_value,
                        "check_time": current_headers["check_time"]
                    })
                except Exception as e:
                    logger.error(f"Ошибка при сохранении заголовков для {url}: {str(e)}")
        logger.info(f"Проверка заголовков безопасности завершена: {len(issues)} проблем обнаружено")
        return {"issues": issues, "changes": changes}