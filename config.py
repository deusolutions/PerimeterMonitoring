"""
Модуль конфигурации системы мониторинга
"""
import os
from dotenv import load_dotenv

# Загрузка переменных окружения из .env файла
load_dotenv()

# Общие настройки
DEBUG = os.getenv("DEBUG", "False") == "True"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "3600"))  # интервал сканирования в секундах

# Настройки IP сканера
IP_RANGES = os.getenv("IP_RANGES", "").split(",")  # список диапазонов IP через запятую
IP_SCAN_TIMEOUT = int(os.getenv("IP_SCAN_TIMEOUT", "2"))  # таймаут в секундах

# Настройки мониторинга сайтов
WEBSITES = os.getenv("WEBSITES", "").split(",")  # список URL сайтов через запятую
WEBSITE_TIMEOUT = int(os.getenv("WEBSITE_TIMEOUT", "5"))  # таймаут в секундах
HTTP_STATUS_ALERT = list(map(int, os.getenv("HTTP_STATUS_ALERT", "500,502,503,504").split(",")))

# Настройки проверки сертификатов
CERT_EXPIRY_ALERT_DAYS = int(os.getenv("CERT_EXPIRY_ALERT_DAYS", "30"))  # предупреждение за N дней

# Настройки уведомлений
NOTIFICATION_EMAIL = os.getenv("NOTIFICATION_EMAIL", "admin@example.com")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.example.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")

# Настройки для Slack уведомлений
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
USE_SLACK = os.getenv("USE_SLACK", "False") == "True"

# Настройки базы данных
DB_TYPE = os.getenv("DB_TYPE", "sqlite")  # sqlite, postgresql, mysql
DB_NAME = os.getenv("DB_NAME", "monitoring.db")
DB_USER = os.getenv("DB_USER", "")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_HOST = os.getenv("DB_HOST", "")
DB_PORT = os.getenv("DB_PORT", "")

# Дополнительные настройки
PORT_SCAN_ENABLED = os.getenv("PORT_SCAN_ENABLED", "True") == "True"
COMMON_PORTS = list(map(int, os.getenv("COMMON_PORTS", "21,22,23,25,53,80,443,3306,3389,5432,8080").split(",")))

DNS_MONITOR_ENABLED = os.getenv("DNS_MONITOR_ENABLED", "True") == "True"
DNS_RECORD_TYPES = os.getenv("DNS_RECORD_TYPES", "A,AAAA,MX,NS,TXT").split(",")

SECURITY_HEADERS_CHECK_ENABLED = os.getenv("SECURITY_HEADERS_CHECK_ENABLED", "True") == "True"
SECURITY_HEADERS = os.getenv("SECURITY_HEADERS", "X-Content-Type-Options,X-Frame-Options,Content-Security-Policy,Strict-Transport-Security").split(",")
SECURITY_HEADERS_TIMEOUT = float(os.getenv("SECURITY_HEADERS_TIMEOUT", "10.0"))
SECURITY_HEADERS_USER_AGENT = os.getenv("SECURITY_HEADERS_USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36")
SECURITY_HEADERS_VERIFY_SSL = os.getenv("SECURITY_HEADERS_VERIFY_SSL", "False") == "True"