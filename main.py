"""
Основной модуль системы мониторинга периметра
"""
import logging
import os
import time
import schedule
from datetime import datetime

# Импорт модулей системы
from core.database import Database
from core.notification import NotificationManager
from modules.ip_scanner import IPScanner
from modules.website_monitor import WebsiteMonitor
from modules.cert_checker import CertificateChecker
from modules.port_scanner import PortScanner
from modules.dns_monitor import DNSMonitor
from modules.security_headers import SecurityHeadersChecker
import config

# Настройка логирования
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("monitoring.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("PerimeterMonitoring")

class PerimeterMonitor:
    """Основной класс системы мониторинга"""
    
    def __init__(self):
        logger.info("Инициализация системы мониторинга периметра")
        
        # Создание директории для логов если её нет
        os.makedirs('logs', exist_ok=True)
        
        # Инициализация базы данных
        self.db = Database()
        
        # Проверка наличия конфигурационного файла
        if not os.path.exists('.env'):
            logger.warning("Файл .env не найден, используются значения по умолчанию")
        
        # Инициализация системы уведомлений
        self.notifier = NotificationManager()
        
        # Инициализация модулей мониторинга
        self.ip_scanner = IPScanner(self.db, self.notifier)
        self.website_monitor = WebsiteMonitor(self.db, self.notifier)
        self.cert_checker = CertificateChecker(self.db, self.notifier)
        
        # Инициализация дополнительных модулей
        if config.PORT_SCAN_ENABLED:
            self.port_scanner = PortScanner(self.db, self.notifier)
        
        if config.DNS_MONITOR_ENABLED:
            self.dns_monitor = DNSMonitor(self.db, self.notifier)
        
        if config.SECURITY_HEADERS_CHECK_ENABLED:
            self.headers_checker = SecurityHeadersChecker(self.db, self.notifier)
        
        logger.info("Система мониторинга инициализирована")
    
    def run_ip_scan(self):
        """Запуск сканирования IP-адресов"""
        logger.info("Запуск сканирования IP-адресов")
        try:
            results = self.ip_scanner.scan()
            logger.info(f"Сканирование IP-адресов завершено: {len(results)} изменений обнаружено")
        except Exception as e:
            logger.error(f"Ошибка при сканировании IP-адресов: {str(e)}")
    
    def check_websites(self):
        """Проверка доступности веб-сайтов"""
        logger.info("Запуск проверки доступности веб-сайтов")
        try:
            results = self.website_monitor.check_all()
            logger.info(f"Проверка веб-сайтов завершена: {results['down_count']} сайтов недоступно")
        except Exception as e:
            logger.error(f"Ошибка при проверке веб-сайтов: {str(e)}")
    
    def check_certificates(self):
        """Проверка SSL-сертификатов"""
        logger.info("Запуск проверки SSL-сертификатов")
        try:
            results = self.cert_checker.check_all()
            logger.info(f"Проверка сертификатов завершена: {results['expiring_count']} сертификатов скоро истекают")
        except Exception as e:
            logger.error(f"Ошибка при проверке сертификатов: {str(e)}")
    
    def run_port_scan(self):
        """Сканирование открытых портов"""
        if not config.PORT_SCAN_ENABLED:
            return
        
        logger.info("Запуск сканирования портов")
        try:
            results = self.port_scanner.scan()
            logger.info(f"Сканирование портов завершено: {len(results)} изменений обнаружено")
        except Exception as e:
            logger.error(f"Ошибка при сканировании портов: {str(e)}")
    
    def check_dns_records(self):
        """Проверка DNS-записей"""
        if not config.DNS_MONITOR_ENABLED:
            return
        
        logger.info("Запуск проверки DNS-записей")
        try:
            results = self.dns_monitor.check_all()
            logger.info(f"Проверка DNS-записей завершена: {len(results)} изменений обнаружено")
        except Exception as e:
            logger.error(f"Ошибка при проверке DNS-записей: {str(e)}")
    
    def check_security_headers(self):
        """Проверка заголовков безопасности"""
        if not config.SECURITY_HEADERS_CHECK_ENABLED:
            return
        
        logger.info("Запуск проверки заголовков безопасности")
        try:
            results = self.headers_checker.check_all()
            logger.info(f"Проверка заголовков безопасности завершена: {results['missing_count']} проблем обнаружено")
        except Exception as e:
            logger.error(f"Ошибка при проверке заголовков безопасности: {str(e)}")
    
    def run_all_checks(self):
        """Запуск всех проверок"""
        logger.info("Запуск полного цикла проверок")
        self.run_ip_scan()
        self.check_websites()
        self.check_certificates()
        self.run_port_scan()
        self.check_dns_records()
        self.check_security_headers()
        logger.info("Полный цикл проверок завершен")
    
    def schedule_jobs(self):
        """Настройка расписания проверок"""
        logger.info("Настройка расписания проверок")
        
        # Запуск всех проверок по расписанию
        schedule.every(config.SCAN_INTERVAL).seconds.do(self.run_all_checks)
        
        # Более частые проверки для веб-сайтов
        schedule.every(max(300, config.SCAN_INTERVAL // 10)).seconds.do(self.check_websites)
        
        logger.info("Расписание проверок настроено")
    
    def run(self):
        """Запуск системы мониторинга"""
        logger.info("Запуск системы мониторинга периметра")
        
        # Инициализация базы данных
        self.db.initialize()
        
        # Запуск первичной проверки
        self.run_all_checks()
        
        # Настройка расписания
        self.schedule_jobs()
        
        # Основной цикл
        try:
            while True:
                schedule.run_pending()
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Получен сигнал остановки, завершение работы...")
        except Exception as e:
            logger.critical(f"Критическая ошибка: {str(e)}")
        finally:
            logger.info("Система мониторинга остановлена")


if __name__ == "__main__":
    monitor = PerimeterMonitor()
    monitor.run()