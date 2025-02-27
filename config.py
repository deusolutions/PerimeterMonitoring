import os
from dotenv import load_dotenv

load_dotenv()

# Основные настройки
DB_NAME = os.getenv('DB_NAME', 'monitoring.db')
FLASK_SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-here') # Нужно установить надежный ключ!
SCAN_INTERVAL = int(os.getenv('SCAN_INTERVAL', 300))  # Интервал сканирования в секундах

# Мониторинг IP
IP_RANGES = os.getenv('IP_RANGES', '127.0.0.1').split(',')
IP_SCAN_TIMEOUT = float(os.getenv('IP_SCAN_TIMEOUT', 1.0))
IP_SCAN_INTERVAL = int(os.getenv('IP_SCAN_INTERVAL', 60)) #В секундах


# Мониторинг веб-сайтов
WEBSITES = os.getenv('WEBSITES', 'http://example.com').split(',')
WEBSITE_TIMEOUT = float(os.getenv('WEBSITE_TIMEOUT', 10.0))
HTTP_STATUS_ALERT = [400, 403, 404, 500, 502, 503]
WEBSITE_CHECK_INTERVAL = int(os.getenv('WEBSITE_CHECK_INTERVAL', 60)) #В секундах

# Мониторинг сертификатов
CERT_EXPIRY_ALERT_DAYS = int(os.getenv('CERT_EXPIRY_ALERT_DAYS', 30))
CERTIFICATE_CHECK_INTERVAL = int(os.getenv('CERTIFICATE_CHECK_INTERVAL', 24))  #  В часах

# Мониторинг портов
PORT_SCAN_ENABLED = os.getenv('PORT_SCAN_ENABLED', 'True').lower() == 'true'
PORT_SCAN_TIMEOUT = float(os.getenv('PORT_SCAN_TIMEOUT', 0.5))
PORT_SCAN_THREADS = int(os.getenv('PORT_SCAN_THREADS', 10))
COMMON_PORTS = [int(p) for p in os.getenv('COMMON_PORTS', '21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443').split(',')]
PORT_SCAN_INTERVAL = int(os.getenv('PORT_SCAN_INTERVAL', 24)) #В часах

# Мониторинг DNS
DNS_MONITOR_ENABLED = os.getenv('DNS_MONITOR_ENABLED', 'True').lower() == 'true'
DNS_TIMEOUT = float(os.getenv('DNS_TIMEOUT', 3.0))
DNS_RECORD_TYPES = os.getenv('DNS_RECORD_TYPES', 'A,AAAA,MX,NS,TXT,CNAME,SOA').split(',')
DNS_NAMESERVERS = os.getenv('DNS_NAMESERVERS', '').split(',') if os.getenv('DNS_NAMESERVERS') else []
DNS_CHECK_INTERVAL = int(os.getenv('DNS_CHECK_INTERVAL', 24))#В часах

# Проверка заголовков безопасности
SECURITY_HEADERS_CHECK_ENABLED = os.getenv('SECURITY_HEADERS_CHECK_ENABLED', 'True').lower() == 'true'
SECURITY_HEADERS = ['Strict-Transport-Security', 'X-XSS-Protection', 'X-Frame-Options', 'X-Content-Type-Options']
SECURITY_HEADERS_TIMEOUT = float(os.getenv('SECURITY_HEADERS_TIMEOUT', 10.0))
SECURITY_HEADERS_USER_AGENT = os.getenv('SECURITY_HEADERS_USER_AGENT', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
SECURITY_HEADERS_VERIFY_SSL = os.getenv('SECURITY_HEADERS_VERIFY_SSL', 'False').lower() == 'true'
HEADERS_CHECK_INTERVAL = int(os.getenv('HEADERS_CHECK_INTERVAL', 24))#В часах

# Добавление токена и ID чата для Telegram уведомлений
TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN', '')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID', '')