# config.py
import os
from dotenv import load_dotenv

load_dotenv()

# Утилита для очистки значения от комментариев
def clean_env_value(value: str) -> str:
    return value.split('#')[0].strip() if value else value

# Отладочный вывод для проверки значений из .env
print(f"DEBUG: IP_SCAN_INTERVAL raw from env: {os.getenv('IP_SCAN_INTERVAL')}")

# Основные настройки
DB_NAME = clean_env_value(os.getenv('DB_NAME', 'monitoring.db'))
FLASK_SECRET_KEY = clean_env_value(os.getenv('FLASK_SECRET_KEY', 'your-secret-key-here'))  # Нужно установить надежный ключ!
SCAN_INTERVAL = int(clean_env_value(os.getenv('SCAN_INTERVAL', '300')))  # Интервал сканирования в секундах

# Мониторинг IP
IP_RANGES = clean_env_value(os.getenv('IP_RANGES', '127.0.0.1')).split(',')
IP_SCAN_TIMEOUT = float(clean_env_value(os.getenv('IP_SCAN_TIMEOUT', '1.0')))
IP_SCAN_INTERVAL = int(clean_env_value(os.getenv('IP_SCAN_INTERVAL', '60')))  # В секундах

# Мониторинг веб-сайтов
WEBSITES = clean_env_value(os.getenv('WEBSITES', 'http://example.com')).split(',')
WEBSITE_TIMEOUT = float(clean_env_value(os.getenv('WEBSITE_TIMEOUT', '10.0')))
HTTP_STATUS_ALERT = [400, 403, 404, 500, 502, 503]
WEBSITE_CHECK_INTERVAL = int(clean_env_value(os.getenv('WEBSITE_CHECK_INTERVAL', '60')))  # В секундах

# Мониторинг сертификатов
CERT_EXPIRY_ALERT_DAYS = int(clean_env_value(os.getenv('CERT_EXPIRY_ALERT_DAYS', '30')))
CERTIFICATE_CHECK_INTERVAL = int(clean_env_value(os.getenv('CERTIFICATE_CHECK_INTERVAL', '24')))  # В часах

# Мониторинг портов
PORT_SCAN_ENABLED = clean_env_value(os.getenv('PORT_SCAN_ENABLED', 'True')).lower() == 'true'
PORT_SCAN_TIMEOUT = float(clean_env_value(os.getenv('PORT_SCAN_TIMEOUT', '0.5')))
PORT_SCAN_THREADS = int(clean_env_value(os.getenv('PORT_SCAN_THREADS', '10')))
COMMON_PORTS = [int(p) for p in clean_env_value(os.getenv('COMMON_PORTS', '21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443')).split(',')]
PORT_SCAN_INTERVAL = int(clean_env_value(os.getenv('PORT_SCAN_INTERVAL', '24')))  # В часах

# Мониторинг DNS
DNS_MONITOR_ENABLED = clean_env_value(os.getenv('DNS_MONITOR_ENABLED', 'True')).lower() == 'true'
DNS_TIMEOUT = float(clean_env_value(os.getenv('DNS_TIMEOUT', '3.0')))
DNS_RECORD_TYPES = clean_env_value(os.getenv('DNS_RECORD_TYPES', 'A,AAAA,MX,NS,TXT,CNAME,SOA')).split(',')
DNS_NAMESERVERS = clean_env_value(os.getenv('DNS_NAMESERVERS', '')).split(',') if clean_env_value(os.getenv('DNS_NAMESERVERS')) else []
DNS_CHECK_INTERVAL = int(clean_env_value(os.getenv('DNS_CHECK_INTERVAL', '24')))  # В часах

# Проверка заголовков безопасности
SECURITY_HEADERS_CHECK_ENABLED = clean_env_value(os.getenv('SECURITY_HEADERS_CHECK_ENABLED', 'True')).lower() == 'true'
SECURITY_HEADERS = ['Strict-Transport-Security', 'X-XSS-Protection', 'X-Frame-Options', 'X-Content-Type-Options']
SECURITY_HEADERS_TIMEOUT = float(clean_env_value(os.getenv('SECURITY_HEADERS_TIMEOUT', '10.0')))
SECURITY_HEADERS_USER_AGENT = clean_env_value(os.getenv('SECURITY_HEADERS_USER_AGENT', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'))
SECURITY_HEADERS_VERIFY_SSL = clean_env_value(os.getenv('SECURITY_HEADERS_VERIFY_SSL', 'False')).lower() == 'true'
HEADERS_CHECK_INTERVAL = int(clean_env_value(os.getenv('HEADERS_CHECK_INTERVAL', '24')))  # В часах

# Уведомления через Telegram
TELEGRAM_TOKEN = clean_env_value(os.getenv('TELEGRAM_TOKEN', ''))
TELEGRAM_CHAT_ID = clean_env_value(os.getenv('TELEGRAM_CHAT_ID', ''))