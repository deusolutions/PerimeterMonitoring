import logging
import socket
import ssl
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

import config
from core.database import Database
from core.notification import NotificationManager

logger = logging.getLogger("CertificateChecker")

class CertificateChecker:
    def __init__(self, db: Database, notifier: NotificationManager):
        self.db = db
        self.notifier = notifier
        self.websites = config.WEBSITES
        self.expiry_alert_days = config.CERT_EXPIRY_ALERT_DAYS
    
    def _get_domain_from_url(self, url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed_url = urlparse(url)
        return parsed_url.netloc.split(':')[0]
    
    def _get_cert_info(self, domain: str, port: int = 443) -> Dict[str, Any]:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(10)
        try:
            conn.connect((domain, port))
            cert = conn.getpeercert()
            subject = dict(x[0] for x in cert['subject'])
            issuer = dict(x[0] for x in cert['issuer'])
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_to_expiry = (not_after - datetime.now()).days
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
    
    def check_all(self, domains: Optional[List[str]] = None) -> Dict[str, Any]:
        if domains is None:
            websites = self.websites
        else:
            websites = [self._get_domain_from_url(d) if d.startswith(('http://', 'https://')) else d for d in domains]
        results = []
        expiring_certs = []
        error_count = 0
        logger.info(f"Запуск проверки SSL-сертификатов для {len(websites)} доменов")
        for url in websites:
            try:
                domain = self._get_domain_from_url(url)
                cert_info = self._get_cert_info(domain)
                results.append(cert_info)
                self.db.save_cert_info(cert_info)  # Сохраняем всегда, даже при ошибке
                if cert_info.get("error"):
                    error_count += 1
                    self._notify_cert_error(cert_info)
                    continue
                if cert_info["is_expired"]:
                    expiring_certs.append(cert_info)
                    self._notify_cert_expired(cert_info)
                elif cert_info["is_expiring"]:
                    expiring_certs.append(cert_info)
                    self._notify_cert_expiring(cert_info)
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
        domain = cert_info["domain"]
        error = cert_info["error"]
        title = f"🔴 Ошибка проверки SSL-сертификата для {domain}"
        message = f"Не удалось проверить SSL-сертификат для домена {domain}.\n"
        message += f"Ошибка: {error}\n"
        self.notifier.send_notification(title, message, priority="high")
    
    def _notify_cert_changed(self, old_cert: Dict[str, Any], new_cert: Dict[str, Any]) -> None:
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