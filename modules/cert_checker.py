# modules/cert_checker.py
import logging
import ssl
import socket
from datetime import datetime
from typing import Dict, List, Any
import config

logger = logging.getLogger(__name__)

class CertificateChecker:
    def __init__(self, db, notifier):
        self.db = db
        self.notifier = notifier
        self.expiry_alert_days = config.CERT_EXPIRY_ALERT_DAYS
        self.ssl_port = 443
        self.timeout = 5.0

    def _check_certificate(self, domain: str) -> Dict[str, Any]:
        cert_info = {
            "domain": domain,
            "common_name": None,
            "issuer": None,
            "organization": None,
            "not_before": None,
            "not_after": None,
            "days_to_expiry": None,
            "is_expiring": False,
            "is_expired": False,
            "error": None,
            "check_time": datetime.now()
        }
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, self.ssl_port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cert_info["common_name"] = cert.get('subject', {}).get('CN', None)
                    cert_info["issuer"] = cert.get('issuer', {}).get('O', None)
                    cert_info["organization"] = cert.get('subject', {}).get('O', None)
                    cert_info["not_before"] = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y GMT')
                    cert_info["not_after"] = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y GMT')
                    days_to_expiry = (cert_info["not_after"] - datetime.now()).days
                    cert_info["days_to_expiry"] = days_to_expiry
                    cert_info["is_expiring"] = 0 < days_to_expiry <= self.expiry_alert_days
                    cert_info["is_expired"] = days_to_expiry <= 0
        except Exception as e:
            error_msg = f"SSL verification error: {str(e)}"
            cert_info["error"] = error_msg
            logger.error(f"Ошибка при проверке SSL для {domain}: {error_msg}")
            self.notifier.send_notification(
                f"🔴 Ошибка проверки SSL-сертификата для {domain}",
                f"Не удалось проверить SSL-сертификат для домена {domain}.\nОшибка: {error_msg}",
                priority="high"
            )
        return cert_info

    def check_all(self, domains: List[str] = None) -> Dict[str, Any]:
        domains = domains or [r["domain"] for r in self.db.get_all_records("ssl_certificates")]
        logger.info(f"Запуск проверки SSL-сертификатов для {len(domains)} доменов")
        expiring = []
        errors = 0
        for domain in domains:
            cert_info = self._check_certificate(domain)
            if cert_info["error"]:
                errors += 1
            elif cert_info["is_expiring"] or cert_info["is_expired"]:
                expiring.append(cert_info)
            try:
                self.db.save_cert_info(cert_info)
            except Exception as e:
                logger.error(f"Ошибка при сохранении сертификата {domain}: {str(e)}")
        result = {"expiring": expiring, "expiring_count": len(expiring), "errors": errors}
        logger.info(f"Проверка сертификатов завершена. {len(expiring)} сертификатов скоро истекают, {errors} ошибок.")
        return result