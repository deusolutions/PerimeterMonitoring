"""
Модуль мониторинга доступности веб-сайтов
"""
import logging
import requests
import time
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional
from urllib.parse import urlparse

import config
from core.database import Database
from core.notification import NotificationManager

logger = logging.getLogger("WebsiteMonitor")

class WebsiteMonitor:
    """Класс для мониторинга доступности веб-сайтов"""
    
    def __init__(self, db: Database, notifier: NotificationManager):
        self.db = db
        self.notifier = notifier
        self.websites = config.WEBSITES
        self.timeout = config.WEBSITE_TIMEOUT
        self.alert_status_codes = config.HTTP_STATUS_ALERT
    
    def _check_website(self, url: str) -> Dict[str, Any]:
        """
        Проверка доступности отдельного веб-сайта
        
        Args:
            url: URL веб-сайта
            
        Returns:
            Dict: Результаты проверки
        """
        start_time = time.time()
        result = {
            "url": url,
            "is_up": False,
            "status_code": None,
            "response_time": None,
            "error": None,
            "check_time": datetime.now()
        }
        
        try:
            # Добавляем схему, если она отсутствует
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
                
            headers = {
                'User-Agent': 'PerimeterMonitor/1.0 (Security Monitoring)'
            }
            
            response = requests.get(url, timeout=self.timeout, headers=headers, allow_redirects=True)
            
            result["is_up"] = response.status_code < 400
            result["status_code"] = response.status_code
            result["response_time"] = round((time.time() - start_time) * 1000)  # в миллисекундах
            
            # Предупреждение, если статус код в списке для оповещения
            if response.status_code in self.alert_status_codes:
                result["is_up"] = False
                result["error"] = f"HTTP статус {response.status_code}"
            
        except requests.exceptions.Timeout:
            result["error"] = "Timeout"
        except requests.exceptions.ConnectionError:
            result["error"] = "Connection Error"
        except requests.exceptions.TooManyRedirects:
            result["error"] = "Too Many Redirects"
        except requests.exceptions.SSLError:
            result["error"] = "SSL Error"
        except Exception as e:
            result["error"] = str(e)
            
        return result
    
    def check_all(self) -> Dict[str, Any]:
        """
        Проверка всех веб-сайтов
        
        Returns:
            Dict: Результаты проверки
        """
        results = []
        changes = []
        down_count = 0
        
        logger.info(f"Запуск проверки {len(self.websites)} веб-сайтов")
        
        for url in self.websites:
            try:
                check_result = self._check_website(url)
                results.append(check_result)
                
                if not check_result["is_up"]:
                    down_count += 1
                
                # Получение предыдущего состояния из базы данных
                previous_state = self.db.get_website_state(url)
                
                # Если это первая проверка
                if previous_state is None:
                    self.db.save_website_state(check_result)
                    continue
                
                # Проверка наличия изменений в состоянии
                if previous_state["is_up"] != check_result["is_up"]:
                    change = {
                        "url": url,
                        "old_state": previous_state,
                        "new_state": check_result,
                        "change_time": datetime.now()
                    }
                    
                    changes.append(change)
                    
                    # Сохранение изменения в БД
                    self.db.save_website_change(change)
                    
                    # Отправка уведомления об изменении
                    self._notify_status_change(change)
                
                # Обновление текущего состояния
                self.db.save_website_state(check_result)
            
            except Exception as e:
                logger.error(f"Ошибка при проверке сайта {url}: {str(e)}")
        
        logger.info(f"Проверка веб-сайтов завершена. {down_count} сайтов недоступно. Обнаружено {len(changes)} изменений статуса.")
        
        return {
            "results": results,
            "changes": changes,
            "down_count": down_count
        }
    
    def _notify_status_change(self, change: Dict[str, Any]) -> None:
        """
        Отправка уведомления об изменении состояния веб-сайта
        
        Args:
            change: Информация об изменении
        """
        url = change["url"]
        old_state = change["old_state"]
        new_state = change["new_state"]
        
        # Формирование сообщения
        if not old_state["is_up"] and new_state["is_up"]:
            # Сайт снова работает
            title = f"🟢 Сайт {url} снова доступен"
            message = f"Веб-сайт {url} восстановил работу.\n"
            message += f"Время ответа: {new_state['response_time']} мс\n"
            message += f"HTTP статус: {new_state['status_code']}"
        elif old_state["is_up"] and not new_state["is_up"]:
            # Сайт упал
            title = f"🔴 Сайт {url} стал недоступен"
            message = f"Веб-сайт {url} перестал отвечать!\n"
            if new_state["error"]:
                message += f"Ошибка: {new_state['error']}\n"
            if new_state["status_code"]:
                message += f"HTTP статус: {new_state['status_code']}\n"
        else:
            return  # Нет изменений, уведомление не требуется
        
        # Отправка уведомления
        self.notifier.send_notification(title, message, priority="high" if not new_state["is_up"] else "normal")