# main.py
import logging
from typing import Dict, Any
import threading

from core.database import Database
from core.notification import NotificationManager
from core.scheduler import Scheduler
from modules.ip_scanner import IPScanner
from modules.website_monitor import WebsiteMonitor
from modules.cert_checker import CertificateChecker
from modules.port_scanner import PortScanner
from modules.dns_monitor import DNSMonitor
from modules.security_headers import SecurityHeadersChecker
import config

logger = logging.getLogger("PerimeterMonitoring")

class PerimeterMonitor:
    def __init__(self, db_manager: Database):
        self.db = db_manager
        self.notifier = NotificationManager()
        self.ip_scanner = IPScanner(self.db, self.notifier)
        self.website_monitor = WebsiteMonitor(self.db, self.notifier)
        self.cert_checker = CertificateChecker(self.db, self.notifier)
        self.port_scanner = PortScanner(self.db, self.notifier, config)
        self.dns_monitor = DNSMonitor(self.db, self.notifier, config)
        self.headers_checker = SecurityHeadersChecker(self.db, self.notifier, config)
        self.scheduler = Scheduler()
        logger.info("Инициализация системы мониторинга периметра")
        logger.info("Система мониторинга инициализирована")

    def run(self) -> None:
        logger.info("Запуск системы мониторинга периметра")
        # Запускаем полный цикл проверок в фоновом потоке
        threading.Thread(target=self.run_full_check, daemon=True).start()
        self.setup_scheduling()

    def run_full_check(self) -> None:
        logger.info("Запуск полного цикла проверок")
        changes_detected = False

        logger.info("Запуск сканирования IP-адресов")
        ip_changes = self.ip_scanner.scan()
        if ip_changes:
            changes_detected = True
        logger.info(f"Сканирование IP-адресов завершено: {len(ip_changes)} изменений обнаружено")

        logger.info("Запуск проверки доступности веб-сайтов")
        website_result = self.website_monitor.check_all()
        down_count = website_result["down_count"]
        if website_result.get("changes"):
            changes_detected = True
        logger.info(f"Проверка веб-сайтов завершена: {down_count} сайтов недоступно")

        logger.info("Запуск проверки SSL-сертификатов")
        cert_result = self.cert_checker.check_all()
        expiring_count = len(cert_result.get("expiring", []))
        if cert_result.get("changes"):
            changes_detected = True
        logger.info(f"Проверка сертификатов завершена: {expiring_count} сертификатов скоро истекают")

        logger.info("Запуск сканирования портов")
        port_changes = self.port_scanner.scan_all()
        if port_changes:
            changes_detected = True
        logger.info(f"Сканирование портов завершено: {len(port_changes)} изменений обнаружено")

        logger.info("Запуск проверки DNS-записей")
        dns_changes = self.dns_monitor.check_all()
        if dns_changes:
            changes_detected = True
        logger.info(f"Проверка DNS-записей завершена: {len(dns_changes)} изменений обнаружено")

        logger.info("Запуск проверки заголовков безопасности")
        headers_result = self.headers_checker.check_all()
        issues_count = len(headers_result.get("issues", []))
        if headers_result.get("changes"):
            changes_detected = True
        logger.info(f"Проверка заголовков безопасности завершена: {issues_count} проблем обнаружено")

        if changes_detected:
            logger.info("Обнаружены изменения в ходе полного цикла проверок")
        else:
            logger.info("Полный цикл проверок завершен без изменений")

    def setup_scheduling(self) -> None:
        logger.info("Настройка расписания проверок")
        self.scheduler.add_task("run_ip_scan", self.run_ip_scan, config.IP_SCAN_INTERVAL, 'seconds')
        self.scheduler.add_task("check_websites", self.check_websites, config.WEBSITE_CHECK_INTERVAL, 'seconds')
        self.scheduler.add_task("check_certificates", self.check_certificates, config.CERTIFICATE_CHECK_INTERVAL, 'hours')
        self.scheduler.add_task("run_port_scan", self.run_port_scan, config.PORT_SCAN_INTERVAL, 'hours')
        self.scheduler.add_task("check_dns_records", self.check_dns_records, config.DNS_CHECK_INTERVAL, 'hours')
        self.scheduler.add_task("check_security_headers", self.check_security_headers, config.HEADERS_CHECK_INTERVAL, 'hours')
        self.scheduler.start()
        logger.info("Расписание проверок настроено")

    def run_ip_scan(self) -> None:
        logger.info("Запуск сканирования IP по расписанию")
        self.ip_scanner.scan()

    def check_websites(self) -> None:
        logger.info("Запуск проверки веб-сайтов по расписанию")
        self.website_monitor.check_all()

    def check_certificates(self) -> None:
        logger.info("Запуск проверки сертификатов по расписанию")
        self.cert_checker.check_all()

    def run_port_scan(self) -> None:
        logger.info("Запуск сканирования портов по расписанию")
        self.port_scanner.scan_all()

    def check_dns_records(self) -> None:
        logger.info("Запуск проверки DNS по расписанию")
        self.dns_monitor.check_all()

    def check_security_headers(self) -> None:
        logger.info("Запуск проверки заголовков безопасности по расписанию")
        self.headers_checker.check_all()

if __name__ == "__main__":
    pass