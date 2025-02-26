from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
import logging
import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import Database
from core.scheduler import Scheduler
from core.notification import NotificationManager
from modules.ip_scanner import IPScanner
from modules.website_monitor import WebsiteMonitor
from modules.cert_checker import CertificateChecker
from modules.port_scanner import PortScanner
from modules.dns_monitor import DNSMonitor
from modules.security_headers import SecurityHeadersChecker
from urllib.parse import urlparse
import time
import config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = config.FLASK_SECRET_KEY

# Инициализация компонентов
db_manager = Database()
db_manager.initialize()
scheduler = None
notifier = NotificationManager()
ip_scanner = IPScanner(db_manager, notifier)
website_monitor = WebsiteMonitor(db_manager, notifier)
cert_checker = CertificateChecker(db_manager, notifier)
port_scanner = PortScanner(db_manager, config) if config.PORT_SCAN_ENABLED else None
dns_monitor = DNSMonitor(db_manager, config) if config.DNS_MONITOR_ENABLED else None
headers_checker = SecurityHeadersChecker(db_manager, config) if config.SECURITY_HEADERS_CHECK_ENABLED else None

@app.before_request
def initialize():
    global scheduler
    if scheduler is None:
        scheduler = Scheduler()

@app.route('/')
def index():
    ip_count = len(db_manager.get_all_records('ip_scan_results'))
    website_count = len(db_manager.get_all_records('website_monitoring'))
    cert_count = len(db_manager.get_all_records('ssl_certificates'))
    alerts_count = sum(1 for _ in ip_scanner.scan())  # Пример подсчёта инцидентов
    recent_alerts = []  # Здесь можно добавить логику для реальных уведомлений
    expiring_certs = [c for c in db_manager.get_all_records('ssl_certificates') 
                     if c.get('days_to_expiry', 999) < 30]
    return render_template('index.html', 
                          title='Мониторинг периметра',
                          ip_count=ip_count,
                          website_count=website_count,
                          cert_count=cert_count,
                          alerts_count=alerts_count,
                          recent_alerts=recent_alerts,
                          expiring_certs=expiring_certs,
                          current_time=datetime.now())

# IP-сканирование
@app.route('/ip-scan', methods=['GET', 'POST'])
def ip_scan():
    if request.method == 'POST':
        if 'delete' in request.form:
            ip_address = request.form.get('ip_address')
            if ip_address and db_manager.delete_ip_state(ip_address):
                flash('IP-адрес успешно удалён', 'success')
            else:
                flash('Ошибка при удалении IP-адреса', 'danger')
            return redirect(url_for('ip_scan'))
        
        ip_address = request.form.get('ip_address')
        description = request.form.get('description', '')
        check_now = 'check_now' in request.form
        if ip_address:
            try:
                state = {
                    "ip_address": ip_address,
                    "is_up": False,
                    "hostname": "",
                    "description": description,
                    "scan_time": datetime.now()
                }
                db_manager.save_ip_state(state)
                if check_now:
                    ip_scanner.scan([ip_address])
                flash('IP-адрес успешно добавлен', 'success')
            except Exception as e:
                logger.error(f"Ошибка при добавлении IP {ip_address}: {str(e)}")
                flash('Ошибка при добавлении IP-адреса', 'danger')
        else:
            flash('Ошибка: IP-адрес не указан', 'danger')
        return redirect(url_for('ip_scan'))
    
    ip_scan_results = db_manager.get_all_records('ip_scan_results', limit=100)
    return render_template('ip_scan.html', 
                          title='Сканирование IP',
                          results=ip_scan_results,
                          current_time=datetime.now())

@app.route('/ip-details/<ip_address>')
def ip_details(ip_address):
    ip_state = db_manager.get_ip_state(ip_address)
    if not ip_state:
        flash('IP-адрес не найден', 'danger')
        return redirect(url_for('ip_scan'))
    return render_template('ip_details.html', 
                          title=f'Детали IP: {ip_address}',
                          ip_state=ip_state,
                          current_time=datetime.now())

@app.route('/ip-check/<ip_address>')
def ip_check(ip_address):
    ip_scanner.scan([ip_address])
    flash(f'IP-адрес {ip_address} проверен', 'success')
    return redirect(url_for('ip_scan'))

@app.route('/ip-edit/<ip_address>', methods=['GET', 'POST'])
def ip_edit(ip_address):
    if request.method == 'POST':
        description = request.form.get('description', '')
        state = db_manager.get_ip_state(ip_address)
        if state:
            state['description'] = description
            db_manager.save_ip_state(state)
            flash('IP-адрес обновлён', 'success')
        else:
            flash('IP-адрес не найден', 'danger')
        return redirect(url_for('ip_scan'))
    
    ip_state = db_manager.get_ip_state(ip_address)
    if not ip_state:
        flash('IP-адрес не найден', 'danger')
        return redirect(url_for('ip_scan'))
    return render_template('ip_edit.html', 
                          title=f'Редактирование IP: {ip_address}',
                          ip_state=ip_state,
                          current_time=datetime.now())

# Веб-сайты
@app.route('/websites', methods=['GET', 'POST'])
def websites():
    if request.method == 'POST':
        url = request.form.get('url')
        check_now = 'check_now' in request.form
        if url:
            try:
                state = {
                    "url": url,
                    "is_up": False,
                    "status_code": 0,
                    "response_time": 0,
                    "error": "",
                    "check_time": datetime.now()
                }
                db_manager.save_website_state(state)
                if check_now:
                    website_monitor.check_all([url])
                flash('Веб-сайт успешно добавлен', 'success')
            except Exception as e:
                logger.error(f"Ошибка при добавлении сайта {url}: {str(e)}")
                flash('Ошибка при добавлении веб-сайта', 'danger')
        return redirect(url_for('websites'))
    
    website_results = db_manager.get_all_records('website_monitoring', limit=100)
    return render_template('websites.html', 
                          title='Мониторинг веб-сайтов',
                          results=website_results,
                          current_time=datetime.now())

@app.route('/website-details/<path:url>')
def website_details(url):
    website_state = db_manager.get_website_state(url)
    if not website_state:
        flash('Веб-сайт не найден', 'danger')
        return redirect(url_for('websites'))
    return render_template('website_details.html', 
                          title=f'Детали сайта: {url}',
                          website_state=website_state,
                          current_time=datetime.now())

# Сертификаты
@app.route('/certificates', methods=['GET', 'POST'])
def certificates():
    if request.method == 'POST':
        domain = request.form.get('domain')
        port = int(request.form.get('port', 443))
        check_now = 'check_now' in request.form
        if domain:
            try:
                state = {
                    "domain": domain,
                    "common_name": "",
                    "issuer": "",
                    "organization": "",
                    "not_before": "",
                    "not_after": "",
                    "days_to_expiry": 0,
                    "is_expiring": False,
                    "is_expired": False,
                    "check_time": datetime.now()
                }
                db_manager.save_cert_info(state)
                if check_now:
                    cert_checker.check_all([domain])
                flash('Сертификат успешно добавлен', 'success')
            except Exception as e:
                logger.error(f"Ошибка при добавлении сертификата {domain}: {str(e)}")
                flash('Ошибка при добавлении сертификата', 'danger')
        return redirect(url_for('certificates'))
    
    cert_results = db_manager.get_all_records('ssl_certificates', limit=100)
    return render_template('certificates.html', 
                          title='Мониторинг SSL-сертификатов',
                          results=cert_results,
                          current_time=datetime.now())

@app.route('/certificate-details/<domain>')
def certificate_details(domain):
    cert_state = db_manager.get_cert_info(domain)
    if not cert_state:
        flash('Сертификат не найден', 'danger')
        return redirect(url_for('certificates'))
    return render_template('certificate_details.html', 
                          title=f'Детали сертификата: {domain}',
                          cert_state=cert_state,
                          current_time=datetime.now())

# DNS
@app.route('/dns', methods=['GET', 'POST'])
def dns_monitoring():
    if request.method == 'POST':
        domain = request.form.get('domain')
        check_now = 'check_now' in request.form
        if domain and dns_monitor:
            try:
                state = {"domain": domain, "records": {}, "timestamp": time.time()}
                db_manager.save_dns_scan(state)
                if check_now:
                    dns_monitor.check_all([domain])
                flash('Домен для DNS успешно добавлен', 'success')
            except Exception as e:
                logger.error(f"Ошибка при добавлении DNS {domain}: {str(e)}")
                flash('Ошибка при добавлении домена', 'danger')
        return redirect(url_for('dns_monitoring'))
    
    dns_results = db_manager.get_all_records('dns_monitoring', limit=100)
    return render_template('dns.html', 
                          title='Мониторинг DNS',
                          results=dns_results,
                          current_time=datetime.now())

# Порты
@app.route('/ports', methods=['GET', 'POST'])
def port_scanning():
    if request.method == 'POST':
        ip_address = request.form.get('ip_address')
        ports = [int(p) for p in request.form.get('ports', '80,443').split(',')]
        check_now = 'check_now' in request.form
        if ip_address and port_scanner:
            try:
                state = {"ip": ip_address, "ports": [], "timestamp": time.time()}
                db_manager.save_port_scan(state)
                if check_now:
                    port_scanner.scan([ip_address])
                flash('Сканирование портов успешно добавлено', 'success')
            except Exception as e:
                logger.error(f"Ошибка при добавлении портов для {ip_address}: {str(e)}")
                flash('Ошибка при добавлении сканирования портов', 'danger')
        return redirect(url_for('port_scanning'))
    
    port_results = db_manager.get_all_records('port_scanning', limit=100)
    return render_template('ports.html', 
                          title='Сканирование портов',
                          results=port_results,
                          current_time=datetime.now())

# Заголовки безопасности
@app.route('/security-headers', methods=['GET', 'POST'])
def security_headers():
    if request.method == 'POST':
        url = request.form.get('url')
        check_now = 'check_now' in request.form
        if url and headers_checker:
            try:
                state = {"url": url, "headers": {}, "timestamp": time.time()}
                db_manager.save_security_headers_check(state)
                if check_now:
                    headers_checker.check_all([url])
                flash('Проверка заголовков успешно добавлена', 'success')
            except Exception as e:
                logger.error(f"Ошибка при добавлении заголовков для {url}: {str(e)}")
                flash('Ошибка при добавлении проверки заголовков', 'danger')
        return redirect(url_for('security_headers'))
    
    headers_results = db_manager.get_all_records('security_headers', limit=100)
    return render_template('security_headers.html', 
                          title='Заголовки безопасности',
                          results=headers_results,
                          current_time=datetime.now())

# Задачи
@app.route('/tasks', methods=['GET', 'POST'])
def scheduler_tasks():
    if request.method == 'POST':
        task_name = request.form.get('task_name')
        function = request.form.get('function')
        interval = int(request.form.get('interval', 60))
        if task_name and function:
            func_map = {
                'run_ip_scan': lambda: ip_scanner.scan(config.IP_RANGES),
                'check_websites': lambda: website_monitor.check_all(),
                'check_certificates': lambda: cert_checker.check_all(),
                'run_port_scan': lambda: port_scanner.scan(config.IP_RANGES) if port_scanner else None,
                'check_dns_records': lambda: dns_monitor.check_all([urlparse(u).netloc for u in config.WEBSITES]) if dns_monitor else None,
                'check_security_headers': lambda: headers_checker.check_all(config.WEBSITES) if headers_checker else None
            }
            if function in func_map:
                scheduler.add_task(task_name, func_map[function], interval * 60)  # в секундах
                flash(f'Задача {task_name} добавлена', 'success')
            else:
                flash('Недопустимая функция задачи', 'danger')
        return redirect(url_for('scheduler_tasks'))
    
    tasks = scheduler.get_task_info() if scheduler else {}
    return render_template('tasks.html', 
                          title='Управление задачами',
                          tasks=tasks,
                          scheduler_running=scheduler.is_running() if scheduler else False,
                          current_time=datetime.now())

# Уведомления
@app.route('/alerts')
def alerts():
    # Пример данных, нужно интегрировать реальные уведомления
    alerts = [
        {"id": 1, "timestamp": datetime.now().strftime('%H:%M:%S %d.%m.%Y'), "type": "IP Change", "target": "127.0.0.1", "message": "IP unavailable", "severity": "warning", "status": "new"}
    ]
    return render_template('alerts.html', 
                          title='Уведомления и инциденты',
                          alerts=alerts,
                          current_time=datetime.now())

# API endpoints остаются без изменений для краткости
@app.route('/api/tasks', methods=['GET'])
def api_get_tasks():
    if scheduler is None:
        return jsonify({"error": "Планировщик не инициализирован"}), 500
    tasks = scheduler.get_task_info()
    return jsonify({"tasks": tasks})

@app.route('/api/tasks/control', methods=['POST'])
def api_control_task():
    if scheduler is None:
        return jsonify({"error": "Планировщик не инициализирован"}), 500
    data = request.json
    if not data or 'task_name' not in data or 'action' not in data:
        return jsonify({"error": "Отсутствуют обязательные параметры"}), 400
    task_name = data['task_name']
    action = data['action']
    if action == 'pause':
        success = scheduler.pause_task(task_name)
    elif action == 'resume':
        success = scheduler.resume_task(task_name)
    elif action == 'remove':
        success = scheduler.remove_task(task_name)
    else:
        return jsonify({"error": f"Неизвестное действие: {action}"}), 400
    if success:
        return jsonify({"status": "success", "message": f"Действие '{action}' выполнено для задачи '{task_name}'"})
    else:
        return jsonify({"error": f"Не удалось выполнить действие '{action}' для задачи '{task_name}'"}), 404

@app.route('/api/scheduler/control', methods=['POST'])
def api_control_scheduler():
    if scheduler is None:
        return jsonify({"error": "Планировщик не инициализирован"}), 500
    data = request.json
    if not data or 'action' not in data:
        return jsonify({"error": "Отсутствует обязательный параметр 'action'"}), 400
    action = data['action']
    if action == 'start':
        scheduler.start()
        return jsonify({"status": "success", "message": "Планировщик запущен"})
    elif action == 'stop':
        scheduler.stop()
        return jsonify({"status": "success", "message": "Планировщик остановлен"})
    else:
        return jsonify({"error": f"Неизвестное действие: {action}"}), 400

@app.route('/api/data/<table_name>', methods=['GET'])
def api_get_data(table_name):
    allowed_tables = ['ip_scan_results', 'website_monitoring', 'ssl_certificates', 
                     'dns_monitoring', 'port_scanning', 'security_headers']
    if table_name not in allowed_tables:
        return jsonify({"error": f"Доступ к таблице '{table_name}' запрещен"}), 403
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    try:
        data = db_manager.get_all_records(table_name, limit=limit, offset=offset)
        return jsonify({"data": data})
    except Exception as e:
        logger.error(f"Ошибка при получении данных из таблицы {table_name}: {str(e)}")
        return jsonify({"error": f"Ошибка при получении данных: {str(e)}"}), 500

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', title='Страница не найдена',
                          message='Запрошенная страница не существует',
                          current_time=datetime.now()), 404

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Внутренняя ошибка сервера: {str(e)}")
    return render_template('error.html', title='Внутренняя ошибка сервера',
                          message='Произошла внутренняя ошибка сервера. Пожалуйста, попробуйте позже.',
                          current_time=datetime.now()), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)