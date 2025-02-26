import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify

from main import PerimeterMonitor
from core.database import Database
from core.notification import NotificationManager

app = Flask(__name__)

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Инициализация компонентов
db_manager = Database()
monitor = PerimeterMonitor(db_manager)
ip_scanner = monitor.ip_scanner
website_monitor = monitor.website_monitor
cert_checker = monitor.cert_checker
port_scanner = monitor.port_scanner
dns_monitor = monitor.dns_monitor
headers_checker = monitor.headers_checker
scheduler = monitor.scheduler
notifier = NotificationManager()

db_manager.initialize()

@app.route('/')
def index():
    return render_template('index.html', scheduler_running=scheduler.is_running(), current_time=datetime.now())

@app.route('/ip-scan', methods=['GET', 'POST'])
def ip_scan():
    if request.method == 'POST':
        if 'delete' in request.form:
            ip_address = request.form.get('ip_address')
            if db_manager.delete_ip_state(ip_address):
                return redirect(url_for('ip_scan'))
        else:
            ip_address = request.form.get('ip_address')
            description = request.form.get('description', '')
            check_now = 'check_now' in request.form
            try:
                result = {"ip_address": ip_address, "description": description, "scan_time": datetime.now()}
                db_manager.save_ip_state(result)
                if check_now:
                    ip_scanner.scan([ip_address])
                return redirect(url_for('ip_scan'))
            except Exception as e:
                logger.error(f"Ошибка при добавлении IP {ip_address}: {str(e)}")
    status_filter = request.args.get('status')
    results = db_manager.get_all_records('ip_scan_results')
    if status_filter == 'up':
        results = [r for r in results if r['is_up']]
    elif status_filter == 'down':
        results = [r for r in results if not r['is_up']]
    return render_template('ip_scan.html', results=results, current_time=datetime.now())

@app.route('/ip-details/<ip_address>')
def ip_details(ip_address):
    ip_state = db_manager.get_ip_state(ip_address) or {}
    return render_template('ip_details.html', title=f"Детали IP {ip_address}", ip_state=ip_state, current_time=datetime.now())

@app.route('/ip-check/<ip_address>')
def ip_check(ip_address):
    try:
        ip_scanner.scan([ip_address])
        return redirect(url_for('ip_scan'))
    except Exception as e:
        logger.error(f"Ошибка при проверке IP {ip_address}: {str(e)}")
        return redirect(url_for('ip_scan'))

@app.route('/ip-edit/<ip_address>', methods=['GET', 'POST'])
def ip_edit(ip_address):
    if request.method == 'POST':
        description = request.form.get('description')
        try:
            ip_state = db_manager.get_ip_state(ip_address) or {}
            ip_state['description'] = description
            db_manager.save_ip_state(ip_state)
            return redirect(url_for('ip_scan'))
        except Exception as e:
            logger.error(f"Ошибка при редактировании IP {ip_address}: {str(e)}")
    ip_state = db_manager.get_ip_state(ip_address) or {}
    return render_template('ip_edit.html', title=f"Редактировать IP {ip_address}", ip_state=ip_state, current_time=datetime.now())

@app.route('/websites', methods=['GET', 'POST'])
def websites():
    if request.method == 'POST':
        if 'delete' in request.form:
            url = request.form.get('url')
            if db_manager.delete_website_state(url):
                return redirect(url_for('websites'))
        else:
            url = request.form.get('url')
            check_now = 'check_now' in request.form
            try:
                result = {"url": url, "check_time": datetime.now()}
                db_manager.save_website_state(result)
                if check_now:
                    website_monitor.check_all([url])
                return redirect(url_for('websites'))
            except Exception as e:
                logger.error(f"Ошибка при добавлении сайта {url}: {str(e)}")
    status_filter = request.args.get('status')
    results = db_manager.get_all_records('website_monitoring')
    if status_filter == 'up':
        results = [r for r in results if r['is_up']]
    elif status_filter == 'down':
        results = [r for r in results if not r['is_up']]
    return render_template('websites.html', results=results, current_time=datetime.now())

@app.route('/website-details/<path:url>')
def website_details(url):
    website_state = db_manager.get_website_state(url) or {}
    return render_template('website_details.html', title=f"Детали сайта {url}", website_state=website_state, current_time=datetime.now())

@app.route('/website-check/<path:url>')
def website_check(url):
    try:
        website_monitor.check_all([url])
        return redirect(url_for('websites'))
    except Exception as e:
        logger.error(f"Ошибка при проверке сайта {url}: {str(e)}")
        return redirect(url_for('websites'))

@app.route('/website-edit/<path:url>', methods=['GET', 'POST'])
def website_edit(url):
    if request.method == 'POST':
        new_url = request.form.get('url')
        try:
            website_state = db_manager.get_website_state(url) or {}
            website_state['url'] = new_url
            db_manager.save_website_state(website_state)
            if url != new_url:
                db_manager.delete_website_state(url)
            return redirect(url_for('websites'))
        except Exception as e:
            logger.error(f"Ошибка при редактировании сайта {url}: {str(e)}")
    website_state = db_manager.get_website_state(url) or {}
    return render_template('website_edit.html', title=f"Редактировать сайт {url}", website_state=website_state, current_time=datetime.now())

@app.route('/certificates', methods=['GET', 'POST'])
def certificates():
    if request.method == 'POST':
        if 'delete' in request.form:
            domain = request.form.get('domain')
            if db_manager.delete_cert_info(domain):
                return redirect(url_for('certificates'))
        else:
            domain = request.form.get('domain')
            port = request.form.get('port', 443, type=int)
            check_now = 'check_now' in request.form
            try:
                result = {
                    "domain": domain,
                    "check_time": datetime.now(),
                    "common_name": "N/A",
                    "issuer": "N/A",
                    "organization": "N/A",
                    "not_before": None,
                    "not_after": None,
                    "days_to_expiry": 0,
                    "is_expiring": False,
                    "is_expired": False,
                    "error": None
                }
                db_manager.save_cert_info(result)
                if check_now:
                    cert_checker.check_all([domain])
                return redirect(url_for('certificates'))
            except Exception as e:
                logger.error(f"Ошибка при добавлении сертификата {domain}: {str(e)}")
    status_filter = request.args.get('status')
    results = db_manager.get_all_records('ssl_certificates')
    if status_filter == 'valid':
        results = [r for r in results if r['days_to_expiry'] > 0 and not r['is_expiring']]
    elif status_filter == 'expiring_soon':
        results = [r for r in results if r['is_expiring'] and r['days_to_expiry'] > 0]
    elif status_filter == 'expired':
        results = [r for r in results if r['days_to_expiry'] <= 0]
    return render_template('certificates.html', results=results, current_time=datetime.now())

@app.route('/certificate-details/<domain>')
def certificate_details(domain):
    cert_state = db_manager.get_cert_info(domain) or {}
    return render_template('certificate_details.html', title=f"Детали сертификата {domain}", cert_state=cert_state, current_time=datetime.now())

@app.route('/certificate-check/<domain>')
def certificate_check(domain):
    try:
        cert_checker.check_all([domain])
        return redirect(url_for('certificates'))
    except Exception as e:
        logger.error(f"Ошибка при проверке сертификата {domain}: {str(e)}")
        return redirect(url_for('certificates'))

@app.route('/certificate-edit/<domain>', methods=['GET', 'POST'])
def certificate_edit(domain):
    if request.method == 'POST':
        new_domain = request.form.get('domain')
        try:
            cert_state = db_manager.get_cert_info(domain) or {}
            cert_state['domain'] = new_domain
            db_manager.save_cert_info(cert_state)
            if domain != new_domain:
                db_manager.delete_cert_info(domain)
            return redirect(url_for('certificates'))
        except Exception as e:
            logger.error(f"Ошибка при редактировании сертификата {domain}: {str(e)}")
    cert_state = db_manager.get_cert_info(domain) or {}
    return render_template('certificate_edit.html', title=f"Редактировать сертификат {domain}", cert_state=cert_state, current_time=datetime.now())

@app.route('/dns', methods=['GET', 'POST'])
def dns_monitoring():
    if request.method == 'POST':
        if 'delete' in request.form:
            domain = request.form.get('domain')
            if db_manager.delete_dns_records(domain):
                return redirect(url_for('dns_monitoring'))
        else:
            domain = request.form.get('domain')
            check_now = 'check_now' in request.form
            try:
                if check_now:
                    dns_monitor.check_all([domain])
                return redirect(url_for('dns_monitoring'))
            except Exception as e:
                logger.error(f"Ошибка при добавлении DNS {domain}: {str(e)}")
    record_type_filter = request.args.get('record_type')
    results = db_manager.get_all_records('dns_monitoring')
    if record_type_filter:
        results = [r for r in results if r['record_type'] == record_type_filter]
    return render_template('dns.html', results=results, current_time=datetime.now())

@app.route('/dns-check/<domain>')
def dns_check(domain):
    try:
        dns_monitor.check_all([domain])
        return redirect(url_for('dns_monitoring'))
    except Exception as e:
        logger.error(f"Ошибка при проверке DNS {domain}: {str(e)}")
        return redirect(url_for('dns_monitoring'))

@app.route('/ports', methods=['GET', 'POST'])
def port_scanning():
    if request.method == 'POST':
        if 'delete' in request.form:
            ip_address = request.form.get('ip_address')
            if db_manager.delete_port_state(ip_address):
                return redirect(url_for('port_scanning'))
        else:
            ip_address = request.form.get('ip_address')
            ports = request.form.get('ports')
            check_now = 'check_now' in request.form
            try:
                if check_now:
                    port_scanner.scan(ip_address, ports.split(','))
                return redirect(url_for('port_scanning'))
            except Exception as e:
                logger.error(f"Ошибка при добавлении портов для {ip_address}: {str(e)}")
    status_filter = request.args.get('status')
    results = db_manager.get_all_records('port_scanning')
    if status_filter == 'open':
        results = [r for r in results if r['is_open']]
    elif status_filter == 'closed':
        results = [r for r in results if not r['is_open']]
    return render_template('ports.html', results=results, current_time=datetime.now())

@app.route('/port-check/<ip_address>')
def port_check(ip_address):
    try:
        ports = [r['port'] for r in db_manager.get_all_records('port_scanning') if r['ip_address'] == ip_address]
        port_scanner.scan(ip_address, ports)
        return redirect(url_for('port_scanning'))
    except Exception as e:
        logger.error(f"Ошибка при проверке портов для {ip_address}: {str(e)}")
        return redirect(url_for('port_scanning'))

@app.route('/security-headers', methods=['GET', 'POST'])
def security_headers():
    if request.method == 'POST':
        if 'delete' in request.form:
            url = request.form.get('url')
            if db_manager.delete_security_headers(url):
                return redirect(url_for('security_headers'))
        else:
            url = request.form.get('url')
            check_now = 'check_now' in request.form
            try:
                if check_now:
                    headers_checker.check_all([url])
                return redirect(url_for('security_headers'))
            except Exception as e:
                logger.error(f"Ошибка при добавлении заголовков для {url}: {str(e)}")
    status_filter = request.args.get('status')
    results = db_manager.get_all_records('security_headers')
    return render_template('security_headers.html', results=results, current_time=datetime.now())

@app.route('/headers-check/<path:url>')
def headers_check(url):
    try:
        headers_checker.check_all([url])
        return redirect(url_for('security_headers'))
    except Exception as e:
        logger.error(f"Ошибка при проверке заголовков для {url}: {str(e)}")
        return redirect(url_for('security_headers'))

@app.route('/tasks', methods=['GET', 'POST'])
def scheduler_tasks():
    if request.method == 'POST':
        task_name = request.form.get('task_name')
        function = request.form.get('function')
        interval = request.form.get('interval', type=int)
        scheduler.add_task(task_name, function, interval)
        return redirect(url_for('scheduler_tasks'))
    tasks = scheduler.get_task_info()  # Исправлено: get_tasks -> get_task_info
    return render_template('tasks.html', tasks=tasks, scheduler_running=scheduler.is_running(), current_time=datetime.now())

@app.route('/api/tasks/control', methods=['POST'])
def control_task():
    data = request.get_json()
    task_name = data.get('task_name')
    action = data.get('action')
    try:
        if action == 'pause':
            scheduler.pause_task(task_name)
        elif action == 'resume':
            scheduler.resume_task(task_name)
        elif action == 'remove':
            scheduler.remove_task(task_name)
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)})

@app.route('/api/scheduler/control', methods=['POST'])
def control_scheduler():
    data = request.get_json()
    action = data.get('action')
    try:
        if action == 'start':
            scheduler.start()
        elif action == 'stop':
            scheduler.stop()  # Исправлено: shutdown -> stop
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)})

@app.route('/alerts')
def alerts():
    return render_template('alerts.html', alerts=notifier.get_alerts(), current_time=datetime.now())

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', title="500 Internal Server Error", 
                          message="The server encountered an internal error and was unable to complete your request.", 
                          current_time=datetime.now()), 500

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', title="404 Not Found", 
                          message="The requested page could not be found.", 
                          current_time=datetime.now()), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)