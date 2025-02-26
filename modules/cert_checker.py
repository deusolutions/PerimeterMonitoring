"""
Модуль проверки SSL-сертификатов
"""
import logging
import socket
import ssl
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

import config
from core.database import Database
from core.notification import NotificationManager

logger = logging.getLogger("CertificateChecker")

class CertificateChecker:
    """Класс для проверки SSL-сертификатов"""
    
    def __init__(self, db: Database, notifier: NotificationManager):
        self.db = db
        self.notifier = notifier
        self.websites = config.WEBSITES
        self.expiry_alert_days = config.CERT_EXPIRY_ALERT_DAYS
    
    def _get_domain_from_url(self, url: str) -> str:
        """
        Извлечение домена из URL
        
        Args:
            url: URL веб-сайта
            
        Returns:
            str: Доменное имя
        """
        # Добавляем схему, если она отсутствует
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        parsed_url = urlparse(url)
        return parsed_url.netloc.split(':')[0]  # Удаляем порт, если он есть
    
    def _get_cert_info(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """
        Получение информации о SSL-сертификате
        
        Args:
            domain: Доменное имя
            port: Порт (по умолчанию 443)
            
        Returns:
            Dict: Информация о сертификате
        """
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        
        # Устанавливаем таймаут
        conn.settimeout(10)
        
        try:
            conn.connect((domain, port))
            cert = conn.getpeercert()
            
            # Извлечение информации о сертификате
            subject = dict(x[0] for x in cert['subject'])
            issuer = dict(x[0] for x in cert['issuer'])
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            
            # Получение списка альтернативных имен (SAN)
            san = []
            if 'subjectAltName' in cert:
                san = [x[1] for x in cert['subjectAltName'] if x[0] == 'DNS']
            
            # Проверяем, скоро ли истекает срок действия
            now = datetime.now()
            days_to_expiry = (not_after - now).days
            is_expiring = days_to_expiry <= self.expiry_alert_days
            is_expired = days_to_expiry <= 0
            
            return {
                "domain": domain,
                "common_name": subject.get('commonName', 'N/A'),
                "issuer": issuer.get('commonName', 'N/A'),
                "organization": subject.get('organizationName', 'N/A'),
                "not_before": not_before,
                "not_after": not_after,
                "days_to_expiry": days_to_expiry,
                "is_expiring": is_expiring,
                "is_expired": is_expired,
                "san": san,
                "check_time": datetime.now(),
                "error": None
            }
            
        except socket.gaierror:
            return {"domain": domain, "error": "DNS resolution failed", "check_time": datetime.now()}
        except socket.timeout:
            return {"domain": domain, "error": "Connection timeout", "check_time": datetime.now()}
        except ssl.SSLCertVerificationError as e:
            return {"domain": domain, "error": f"SSL verification error: {str(e)}", "check_time": datetime.now()}
        except Exception as e:
            return {"domain": domain, "error": str(e), "check_time": datetime.now()}
        finally:
            conn.close()
    
    def check_all(self) -> Dict[str, Any]:
        """
        Проверка SSL-сертификатов для всех сайтов
        
        Returns:
            Dict: Результаты проверки
        """
        results = []
        expiring_certs = []
        error_count = 0
        
        logger.info(f"Запуск проверки SSL-сертификатов для {len(self.websites)} доменов")
        
        for url in self.websites:
            try:
                domain = self._get_domain_from_url(url)
                cert_info = self._get_cert_info(domain)
                results.append(cert_info)
                
                # Если произошла ошибка при проверке
                if cert_info.get("error"):
                    error_count += 1
                    self._notify_cert_error(cert_info)
                    continue
                
                # Сохранение текущей информации о сертификате
                self.db.save_cert_info(cert_info)
                
                # Проверка на истечение срока действия
                if cert_info["is_expired"]:
                    expiring_certs.append(cert_info)
                    self._notify_cert_expired(cert_info)
                elif cert_info["is_expiring"]:
                    expiring_certs.append(cert_info)
                    self._notify_cert_expiring(cert_info)
                    
                # Проверка на изменение сертификата
                previous_cert = self.db.get_cert_info(domain)
                if previous_cert and previous_cert["not_after"] != cert_info["not_after"]:
                    self._notify_cert_changed(previous_cert, cert_info)
                
            except Exception as e:
                logger.error(f"Ошибка при проверке сертификата для {url}: {str(e)}")
        
        logger.info(f"Проверка сертификатов завершена. {len(expiring_certs)} сертификатов скоро истекают, {error_count} ошибок.")
        
        return {
            "results": results,
            "expiring": expiring_certs,
            "expiring_count": len(expiring_certs),
            "error_count": error_count
        }
    
    def _notify_cert_expiring(self, cert_info: Dict[str, Any]) -> None:
        """
        Отправка уведомления о скором истечении срока действия сертификата
        
        Args:
            cert_info: Информация о сертификате
        """
        domain = cert_info["domain"]
        days = cert_info["days_to_expiry"]
        
        title = f"⚠️ Срок действия SSL-сертификата для {domain} истекает через {days} дней"
        message = f"SSL-сертификат для домена {domain} истекает через {days} дней!\n\n"
        message += f"Издатель: {cert_info['issuer']}\n"
        message += f"Срок действия до: {cert_info['not_after'].strftime('%d.%m.%Y')}\n"
        message += f"Общее имя: {cert_info['common_name']}\n"
        
        if cert_info['organization'] != 'N/A':
            message += f"Организация: {cert_info['organization']}\n"
        
        self.notifier.send_notification(title, message, priority="medium")
    
    def _notify_cert_expired(self, cert_info: Dict[str, Any]) -> None:
        """
        Отправка уведомления об истекшем сертификате
        
        Args:
            cert_info: Информация о сертификате
        """
        domain = cert_info["domain"]
        
        title = f"🔴 SSL-сертификат для {domain} ИСТЕК!"
        message = f"SSL-сертификат для домена {domain} истек!\n\n"
        message += f"Издатель: {cert_info['issuer']}\n"
        message += f"Срок действия истек: {cert_info['not_after'].strftime('%d.%m.%Y')}\n"
        message += f"Общее имя: {cert_info['common_name']}\n"
        
        if cert_info['organization'] != 'N/A':
            message += f"Организация: {cert_info['organization']}\n"
        
        self.notifier.send_notification(title, message, priority="high")
    
    def _notify_cert_error(self, cert_info: Dict[str, Any]) -> None:
        """
        Отправка уведомления об ошибке при проверке сертификата
        
        Args:
            cert_info: Информация об ошибке
        """
        domain = cert_info["domain"]
        error = cert_info["error"]
        
        title = f"🔴 Ошибка проверки SSL-сертификата для {domain}"
        message = f"Не удалось проверить SSL-сертификат для домена {domain}.\n"
        message += f"Ошибка: {error}\n"
        
        self.notifier.send_notification(title, message, priority="high")
    
    def _notify_cert_changed(self, old_cert: Dict[str, Any], new_cert: Dict[str, Any]) -> None:
        """
        Отправка уведомления об изменении сертификата
        
        Args:
            old_cert: Информация о старом сертификате
            new_cert: Информация о новом сертификате
        """
        domain = new_cert["domain"]
        
        title = f"ℹ️ SSL-сертификат для {domain} был изменен"
        message = f"Обнаружено изменение SSL-сертификата для домена {domain}.\n\n"
        message += "Информация о новом сертификате:\n"
        message += f"Издатель: {new_cert['issuer']}\n"
        message += f"Срок действия: с {new_cert['not_before'].strftime('%d.%m.%Y')} по {new_cert['not_after'].strftime('%d.%m.%Y')}\n"
        message += f"Общее имя: {new_cert['common_name']}\n"
        
        if new_cert['organization'] != 'N/A':
            message += f"Организация: {new_cert['organization']}\n"
        
        self.notifier.send_notification(title, message, priority="medium")