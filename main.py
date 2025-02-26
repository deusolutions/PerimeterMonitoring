import logging
import os
import time
import schedule
from datetime import datetime
from urllib.parse import urlparse

from core.database import Database
from core.notification import NotificationManager
from modules.ip_scanner import IPScanner
from modules.website_monitor import WebsiteMonitor
from modules.cert_checker import CertificateChecker
from modules.port_scanner import PortScanner
from modules.dns_monitor import DNSMonitor
from modules.security_headers import SecurityHeadersChecker
import config

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("monitoring.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("PerimeterMonitoring")

class PerimeterMonitor:
    def __init__(self):
        logger.info("Инициализация системы мониторинга периметра")
        os.makedirs('logs', exist_ok=True)
        self.db = Database()
        self.notifier = NotificationManager()
        self.ip_scanner = IPScanner(self.db, self.notifier)
        self.website_monitor = WebsiteMonitor(self.db, self.notifier)
        self.cert_checker = CertificateChecker(self.db, self.notifier)
        self.port_scanner = PortScanner(self.db, config) if config.PORT_SCAN_ENABLED else None
        self.dns_monitor = DNSMonitor(self.db, config) if config.DNS_MONITOR_ENABLED else None
        self.headers_checker = SecurityHeadersChecker(self.db, config) if config.SECURITY_HEADERS_CHECK_ENABLED else None
        logger.info("Система мониторинга инициализирована")
    
    def run_ip_scan(self):
        logger.info("Запуск сканирования IP-адресов")
        try:
            results = self.ip_scanner.scan()
            logger.info(f"Сканирование IP-адресов завершено: {len(results)} изменений обнаружено")
        except Exception as e:
            logger.error(f"Ошибка при сканировании IP-адресов: {str(e)}")
    
    def check_websites(self):
        logger.info("Запуск проверки доступности веб-сайтов")
        try:
            results = self.website_monitor.check_all()
            logger.info(f"Проверка веб-сайтов завершена: {results['down_count']} сайтов недоступно")
        except Exception as e:
            logger.error(f"Ошибка при проверке веб-сайтов: {str(e)}")
    
    def check_certificates(self):
        logger.info("Запуск проверки SSL-сертификатов")
        try:
            results = self.cert_checker.check_all()
            logger.info(f"Проверка сертификатов завершена: {results['expiring_count']} сертификатов скоро истекают")
        except Exception as e:
            logger.error(f"Ошибка при проверке сертификатов: {str(e)}")
    
    def run_port_scan(self):
        if not config.PORT_SCAN_ENABLED or not self.port_scanner:
            return
        logger.info("Запуск сканирования портов")
        try:
            results = self.port_scanner.scan(config.IP_RANGES)
            logger.info(f"Сканирование портов завершено: {len(results)} изменений обнаружено")
        except Exception as e:
            logger.error(f"Ошибка при сканировании портов: {str(e)}")
    
    def check_dns_records(self):
        if not config.DNS_MONITOR_ENABLED or not self.dns_monitor:
            return
        logger.info("Запуск проверки DNS-записей")
        try:
            domains = [urlparse(url).netloc.split(':')[0] if url.startswith(('http://', 'https://')) else url 
                      for url in config.WEBSITES]
            results = self.dns_monitor.check_all(domains)
            logger.info(f"Проверка DNS-записей завершена: {len(results)} изменений обнаружено")
        except Exception as e:
            logger.error(f"Ошибка при проверке DNS-записей: {str(e)}")
    
    def check_security_headers(self):
        if not config.SECURITY_HEADERS_CHECK_ENABLED or not self.headers_checker:
            return
        logger.info("Запуск проверки заголовков безопасности")
        try:
            results = self.headers_checker.check_all(config.WEBSITES)
            logger.info(f"Проверка заголовков безопасности завершена: {len(results)} проблем обнаружено")
        except Exception as e:
            logger.error(f"Ошибка при проверке заголовков безопасности: {str(e)}")
    
    def run_all_checks(self):
        logger.info("Запуск полного цикла проверок")
        self.run_ip_scan()
        self.check_websites()
        self.check_certificates()
        self.run_port_scan()
        self.check_dns_records()
        self.check_security_headers()
        logger.info("Полный цикл проверок завершен")
    
    def schedule_jobs(self):
        logger.info("Настройка расписания проверок")
        schedule.every(config.SCAN_INTERVAL).seconds.do(self.run_all_checks)
        schedule.every(max(300, config.SCAN_INTERVAL // 10)).seconds.do(self.check_websites)
        logger.info("Расписание проверок настроено")
    
    def run(self):
        logger.info("Запуск системы мониторинга периметра")
        self.db.initialize()
        self.run_all_checks()
        self.schedule_jobs()
        try:
            while True:
                schedule.run_pending()
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Получен сигнал остановки, завершение работы...")
        except Exception as e:
            logger.critical(f"Критическая ошибка: {str(e)}")
        finally:
            self.db.close()
            logger.info("Система мониторинга остановлена")

if __name__ == "__main__":
    monitor = PerimeterMonitor()
    monitor.run()