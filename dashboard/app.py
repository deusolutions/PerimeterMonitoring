import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_wtf.csrf import CSRFProtect

from core.notification import NotificationManager
from init import monitor, db_manager
from dashboard.forms import IPForm, WebsiteForm, CertificateForm, DNSForm, PortScanForm, SecurityHeadersForm, TaskForm
import config

app = Flask(__name__)
app.config['SECRET_KEY'] = config.FLASK_SECRET_KEY
csrf = CSRFProtect(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ip_scanner = monitor.ip_scanner
website_monitor = monitor.website_monitor
cert_checker = monitor.cert_checker
port_scanner = monitor.port_scanner
dns_monitor = monitor.dns_monitor
headers_checker = monitor.headers_checker
scheduler = monitor.scheduler
notifier = NotificationManager()

TASK_FUNCTIONS = {
    "run_ip_scan": monitor.run_ip_scan,
    "check_websites": monitor.check_websites,
    "check_certificates": monitor.check_certificates,
    "run_port_scan": monitor.run_port_scan,
    "check_dns_records": monitor.check_dns_records,
    "check_security_headers": monitor.check_security_headers
}

@app.route('/')
def index():
    ip_count = len(db_manager.get_all_records("ip_scan_results"))
    website_count = len(db_manager.get_all_records("website_monitoring"))
    cert_count = len(db_manager.get_all_records("ssl_certificates"))
    alerts_count = 0  # Заменить на реальные данные позже
    expiring_certs = cert_checker.check_all().get("expiring", [])
    return render_template('index.html', scheduler_running=scheduler.is_running(), current_time=datetime.now(),
                           ip_count=ip_count, website_count=website_count, cert_count=cert_count, 
                           alerts_count=alerts_count, expiring_certs=expiring_certs)

@app.route('/ip-scan', methods=['GET', 'POST'])
def ip_scan():
    form = IPForm()
    if form.validate_on_submit():
        if 'delete' in request.form:
            ip_address = request.form.get('ip_address')
            if db_manager.delete_ip_state(ip_address):
                flash(f"IP-адрес {ip_address} удален.", "success")
                return redirect(url_for('ip_scan', page=request.args.get('page', 1, type=int)))
            else:
                flash(f"Не удалось удалить IP-адрес {ip_address}.", "danger")
                page = request.args.get('page', 1, type=int)
                per_page = 10
                total_results = len(db_manager.get_all_records('ip_scan_results'))
                return render_template("error.html", title="Ошибка", message=f"Не удалось удалить IP-адрес {ip_address}", 
                                       page=page, total_results=total_results, per_page=per_page), 500
        else:
            ip_address = form.ip_address.data
            description = form.description.data
            check_now = form.check_now.data
            try:
                result = {"ip_address": ip_address, "description": description, "scan_time": datetime.now()}
                db_manager.save_ip_state(result)
                if check_now:
                    ip_scanner.scan([ip_address])
                flash(f"IP-адрес {ip_address} добавлен.", "success")
                return redirect(url_for('ip_scan', page=request.args.get('page', 1, type=int)))
            except Exception as e:
                logger.error(f"Ошибка при добавлении IP {ip_address}: {str(e)}")
                flash(f"Ошибка при добавлении IP-адреса: {str(e)}", "danger")
                page = request.args.get('page', 1, type=int)
                per_page = 10
                total_results = len(db_manager.get_all_records('ip_scan_results'))
                return render_template("error.html", title="Ошибка", message=f"Ошибка при добавлении IP-адреса: {str(e)}", 
                                       page=page, total_results=total_results, per_page=per_page), 500

    page = request.args.get('page', 1, type=int)
    per_page = 10
    status_filter = request.args.get('status')
    all_results = db_manager.get_all_records('ip_scan_results')
    if status_filter == 'up':
        filtered_results = [r for r in all_results if r['is_up']]
    elif status_filter == 'down':
        filtered_results = [r for r in all_results if not r['is_up']]
    else:
        filtered_results = all_results
    total_results = len(filtered_results)
    results = filtered_results[(page - 1) * per_page: page * per_page]
    return render_template('ip_scan.html', results=results, current_time=datetime.now(), form=form, page=page,
                           total_results=total_results, per_page=per_page)

@app.route('/ip-details/<ip_address>')
def ip_details(ip_address):
    ip_state = db_manager.get_ip_state(ip_address) or {}
    return render_template('ip_details.html', title=f"Детали IP {ip_address}", ip_state=ip_state, current_time=datetime.now())

@app.route('/ip-check/<ip_address>')
def ip_check(ip_address):
    try:
        ip_scanner.scan([ip_address])
        flash(f"IP-адрес {ip_address} проверен.", "success")
        return redirect(url_for('ip_scan'))
    except Exception as e:
        logger.error(f"Ошибка при проверке IP {ip_address}: {str(e)}")
        flash(f"Ошибка при проверке IP-адреса: {str(e)}", "danger")
        return redirect(url_for('ip_scan'))

@app.route('/ip-edit/<ip_address>', methods=['GET', 'POST'])
def ip_edit(ip_address):
    form = IPForm()
    ip_state = db_manager.get_ip_state(ip_address) or {}
    if form.validate_on_submit():
        description = form.description.data
        try:
            ip_state['description'] = description
            db_manager.save_ip_state(ip_state)
            flash(f"Описание для IP-адреса {ip_address} обновлено.", "success")
            return redirect(url_for('ip_scan'))
        except Exception as e:
            logger.error(f"Ошибка при редактировании IP {ip_address}: {str(e)}")
            flash(f"Ошибка при редактировании IP-адреса: {str(e)}", "danger")
            return render_template("error.html", title="Ошибка", message=f"Ошибка при редактировании описания IP {ip_address}", 
                                   current_time=datetime.now())
    form.ip_address.data = ip_state.get('ip_address')
    form.description.data = ip_state.get('description')
    return render_template('ip_edit.html', title=f"Редактировать IP {ip_address}", ip_state=ip_state, 
                           current_time=datetime.now(), form=form)

@app.route('/websites', methods=['GET', 'POST'])
def websites():
    form = WebsiteForm()
    if form.validate_on_submit():
        if 'delete' in request.form:
            url = request.form.get('url')
            if db_manager.delete_website_state(url):
                flash(f"Веб-сайт {url} удален.", "success")
                return redirect(url_for('websites', page=request.args.get('page', 1, type=int)))
            else:
                flash(f"Не удалось удалить веб-сайт {url}.", "danger")
                page = request.args.get('page', 1, type=int)
                per_page = 10
                total_results = len(db_manager.get_all_records('website_monitoring'))
                return render_template("error.html", title="Ошибка", message=f"Не удалось удалить веб-сайт {url}", 
                                       page=page, total_results=total_results, per_page=per_page), 500
        else:
            url = form.url.data
            check_now = form.check_now.data
            try:
                result = {"url": url, "check_time": datetime.now()}
                db_manager.save_website_state(result)
                if check_now:
                    website_monitor.check_all([url])
                flash(f"Веб-сайт {url} добавлен.", "success")
                return redirect(url_for('websites', page=request.args.get('page', 1, type=int)))
            except Exception as e:
                logger.error(f"Ошибка при добавлении сайта {url}: {str(e)}")
                flash(f"Ошибка при добавлении веб-сайта: {str(e)}", "danger")
                page = request.args.get('page', 1, type=int)
                per_page = 10
                total_results = len(db_manager.get_all_records('website_monitoring'))
                return render_template("error.html", title="Ошибка", message=f"Ошибка при добавлении сайта {url}", 
                                       page=page, total_results=total_results, per_page=per_page), 500
    page = request.args.get('page', 1, type=int)
    per_page = 10
    status_filter = request.args.get('status')
    all_results = db_manager.get_all_records('website_monitoring')
    if status_filter == 'up':
        filtered_results = [r for r in all_results if r['is_up']]
    elif status_filter == 'down':
        filtered_results = [r for r in all_results if not r['is_up']]
    else:
        filtered_results = all_results
    total_results = len(filtered_results)
    results = filtered_results[(page - 1) * per_page: page * per_page]
    return render_template('websites.html', results=results, current_time=datetime.now(), form=form, page=page,
                           total_results=total_results, per_page=per_page)

@app.route('/website-details/<path:url>')
def website_details(url):
    website_state = db_manager.get_website_state(url) or {}
    return render_template('website_details.html', title=f"Детали сайта {url}", website_state=website_state, 
                           current_time=datetime.now())

@app.route('/website-check/<path:url>')
def website_check(url):
    try:
        website_monitor.check_all([url])
        flash(f"Веб-сайт {url} проверен.", "success")
        return redirect(url_for('websites'))
    except Exception as e:
        logger.error(f"Ошибка при проверке сайта {url}: {str(e)}")
        flash(f"Ошибка при проверке веб-сайта: {str(e)}", "danger")
        return redirect(url_for('websites'))

@app.route('/website-edit/<int:website_id>', methods=['GET', 'POST'])
def website_edit(website_id):
    form = WebsiteForm()
    website_state = db_manager.get_website_state_by_id(website_id)
    if not website_state:
        flash("Веб-сайт не найден.", "danger")
        return redirect(url_for('websites'))
    if form.validate_on_submit():
        new_url = form.url.data
        try:
            website_state['url'] = new_url
            db_manager.update_website_state_by_id(website_id, website_state)
            flash("Веб-сайт успешно обновлен.", "success")
            return redirect(url_for('websites'))
        except Exception as e:
            logger.error(f"Ошибка при редактировании сайта: {str(e)}")
            flash(f"Ошибка при редактировании сайта: {str(e)}", "danger")
            return render_template('error.html', title="Ошибка", message="Ошибка при редактировании сайта", 
                                   current_time=datetime.now())
    form.url.data = website_state.get('url')
    return render_template('website_edit.html', title=f"Редактировать сайт", website_state=website_state, 
                           current_time=datetime.now(), form=form)

@app.route('/certificates', methods=['GET', 'POST'])
def certificates():
    form = CertificateForm()
    if form.validate_on_submit():
        if 'delete' in request.form:
            domain = request.form.get('domain')
            if db_manager.delete_cert_info(domain):
                flash(f"Сертификат для домена {domain} удален.", "success")
                return redirect(url_for('certificates', page=request.args.get('page', 1, type=int)))
            else:
                flash(f"Не удалось удалить сертификат для домена {domain}.", "danger")
                page = request.args.get('page', 1, type=int)
                per_page = 10
                total_results = len(db_manager.get_all_records('ssl_certificates'))
                return render_template("error.html", title="Ошибка", message=f"Не удалось удалить сертификат {domain}", 
                                       page=page, total_results=total_results, per_page=per_page), 500
        else:
            domain = form.domain.data
            port = form.port.data
            check_now = form.check_now.data
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
                flash(f"Сертификат для домена {domain} добавлен.", "success")
                return redirect(url_for('certificates', page=request.args.get('page', 1, type=int)))
            except Exception as e:
                logger.error(f"Ошибка при добавлении сертификата {domain}: {str(e)}")
                flash(f"Ошибка при добавлении сертификата: {str(e)}", "danger")
                page = request.args.get('page', 1, type=int)
                per_page = 10
                total_results = len(db_manager.get_all_records('ssl_certificates'))
                return render_template("error.html", title="Ошибка", message=f"Ошибка при добавлении сертификата: {str(e)}", 
                                       page=page, total_results=total_results, per_page=per_page), 500
    page = request.args.get('page', 1, type=int)
    per_page = 10
    status_filter = request.args.get('status')
    all_results = db_manager.get_all_records('ssl_certificates')
    if status_filter == 'valid':
        filtered_results = [r for r in all_results if r.get('days_to_expiry', 0) > 0 and not r.get('is_expiring', False)]
    elif status_filter == 'expiring_soon':
        filtered_results = [r for r in all_results if r.get('is_expiring', False) and r.get('days_to_expiry', 0) > 0]
    elif status_filter == 'expired':
        filtered_results = [r for r in all_results if r.get('days_to_expiry', 0) <= 0]
    else:
        filtered_results = all_results
    total_results = len(filtered_results)
    results = filtered_results[(page - 1) * per_page: page * per_page]
    return render_template('certificates.html', results=results, current_time=datetime.now(), form=form, page=page,
                           total_results=total_results, per_page=per_page)

@app.route('/certificate-details/<domain>')
def certificate_details(domain):
    cert_state = db_manager.get_cert_info(domain) or {}
    return render_template('certificate_details.html', title=f"Детали сертификата {domain}", cert_state=cert_state, 
                           current_time=datetime.now())

@app.route('/certificate-check/<domain>')
def certificate_check(domain):
    try:
        cert_checker.check_all([domain])
        flash(f"Сертификат для домена {domain} проверен.", "success")
        return redirect(url_for('certificates'))
    except Exception as e:
        logger.error(f"Ошибка при проверке сертификата {domain}: {str(e)}")
        flash(f"Ошибка при проверке сертификата: {str(e)}", "danger")
        return redirect(url_for('certificates'))

@app.route('/certificate-edit/<int:cert_id>', methods=['GET', 'POST'])
def certificate_edit(cert_id):
    form = CertificateForm()
    cert_state = db_manager.get_cert_info_by_id(cert_id)
    if not cert_state:
        flash("Сертификат не найден", "danger")
        return redirect(url_for('certificates'))
    if form.validate_on_submit():
        new_domain = form.domain.data
        try:
            cert_state['domain'] = new_domain
            db_manager.update_cert_info_by_id(cert_id, cert_state)
            flash("Сертификат успешно обновлен.", "success")
            return redirect(url_for('certificates'))
        except Exception as e:
            logger.error(f"Ошибка при редактировании сертификата: {str(e)}")
            flash(f"Ошибка при редактировании сертификата: {str(e)}", "danger")
            return render_template('error.html', title="Ошибка", message=f"Ошибка при редактировании сертификата", 
                                   current_time=datetime.now())
    form.domain.data = cert_state.get('domain')
    form.port.data = cert_state.get('port', 443)
    return render_template('certificate_edit.html', title=f"Редактировать сертификат", cert_state=cert_state, 
                           current_time=datetime.now(), form=form)

@app.route('/dns', methods=['GET', 'POST'])
def dns_monitoring():
    form = DNSForm()
    if form.validate_on_submit():
        if 'delete' in request.form:
            domain = request.form.get('domain')
            if db_manager.delete_dns_records(domain):
                flash(f"DNS-записи для домена {domain} удалены.", "success")
                return redirect(url_for('dns_monitoring', page=request.args.get('page', 1, type=int)))
            else:
                flash(f"Не удалось удалить DNS-записи для домена {domain}.", "danger")
                page = request.args.get('page', 1, type=int)
                per_page = 10
                total_results = len(db_manager.get_all_records('dns_monitoring'))
                return render_template("error.html", title="Ошибка", message=f"Не удалось удалить DNS {domain}", 
                                       page=page, total_results=total_results, per_page=per_page), 500
        else:
            domain = form.domain.data
            check_now = form.check_now.data
            try:
                if check_now:
                    dns_monitor.check_all([domain])
                flash(f"Мониторинг DNS для домена {domain} добавлен.", "success")
                return redirect(url_for('dns_monitoring', page=request.args.get('page', 1, type=int)))
            except Exception as e:
                logger.error(f"Ошибка при добавлении DNS {domain}: {str(e)}")
                flash(f"Ошибка при добавлении DNS: {str(e)}", "danger")
                page = request.args.get('page', 1, type=int)
                per_page = 10
                total_results = len(db_manager.get_all_records('dns_monitoring'))
                return render_template("error.html", title="Ошибка", message=f"Ошибка при добавлении DNS {domain}", 
                                       page=page, total_results=total_results, per_page=per_page), 500
    page = request.args.get('page', 1, type=int)
    per_page = 10
    record_type_filter = request.args.get('record_type')
    all_results = db_manager.get_all_records('dns_monitoring')
    if record_type_filter:
        filtered_results = [r for r in all_results if r['record_type'] == record_type_filter]
    else:
        filtered_results = all_results
    total_results = len(filtered_results)
    results = filtered_results[(page-1) * per_page: page * per_page]
    return render_template('dns.html', results=results, current_time=datetime.now(), form=form, page=page,
                           total_results=total_results, per_page=per_page)

@app.route('/dns-check/<domain>')
def dns_check(domain):
    try:
        dns_monitor.check_all([domain])
        flash(f"DNS-записи для домена {domain} проверены.", "success")
        return redirect(url_for('dns_monitoring'))
    except Exception as e:
        logger.error(f"Ошибка при проверке DNS {domain}: {str(e)}")
        flash(f"Ошибка при проверке DNS: {str(e)}", "danger")
        return redirect(url_for('dns_monitoring'))

@app.route('/ports', methods=['GET', 'POST'])
def port_scanning():
    form = PortScanForm()
    if form.validate_on_submit():
        if 'delete' in request.form:
            ip_address = request.form.get('ip_address')
            if db_manager.delete_port_state(ip_address):
                flash(f"Сканирование портов для IP-адреса {ip_address} удалено.", "success")
                return redirect(url_for('port_scanning', page=request.args.get('page', 1, type=int)))
            else:
                flash(f"Не удалось удалить сканирование портов для IP-адреса {ip_address}.", "danger")
                page = request.args.get('page', 1, type=int)
                per_page = 10
                total_results = len(db_manager.get_all_records('port_scanning'))
                return render_template("error.html", title="Ошибка", message=f"Не удалось удалить порты для {ip_address}", 
                                       page=page, total_results=total_results, per_page=per_page), 500
        else:
            ip_address = form.ip_address.data
            ports = form.ports.data
            check_now = form.check_now.data
            try:
                if check_now:
                    port_scanner.scan(ip_address, ports.split(','))
                flash(f"Сканирование портов для IP-адреса {ip_address} добавлено.", "success")
                return redirect(url_for('port_scanning', page=request.args.get('page', 1, type=int)))
            except Exception as e:
                logger.error(f"Ошибка при добавлении портов для {ip_address}: {str(e)}")
                flash(f"Ошибка при добавлении портов: {str(e)}", "danger")
                page = request.args.get('page', 1, type=int)
                per_page = 10
                total_results = len(db_manager.get_all_records('port_scanning'))
                return render_template("error.html", title="Ошибка", message=f"Ошибка при сканировании портов для {ip_address}", 
                                       page=page, total_results=total_results, per_page=per_page), 500
    page = request.args.get('page', 1, type=int)
    per_page = 10
    status_filter = request.args.get('status')
    all_results = db_manager.get_all_records('port_scanning')
    if status_filter == 'open':
        filtered_results = [r for r in all_results if r['is_open']]
    elif status_filter == 'closed':
        filtered_results = [r for r in all_results if not r['is_open']]
    else:
        filtered_results = all_results
    total_results = len(filtered_results)
    results = filtered_results[(page - 1) * per_page: page * per_page]
    return render_template('ports.html', results=results, current_time=datetime.now(), form=form, page=page,
                           total_results=total_results, per_page=per_page)

@app.route('/port-check/<ip_address>')
def port_check(ip_address):
    try:
        ports = [str(r['port']) for r in db_manager.get_all_records('port_scanning') if r['ip_address'] == ip_address]
        port_scanner.scan(ip_address, ports)
        flash(f"Порты для IP-адреса {ip_address} проверены.", "success")
        return redirect(url_for('port_scanning'))
    except Exception as e:
        logger.error(f"Ошибка при проверке портов для {ip_address}: {str(e)}")
        flash(f"Ошибка при проверке портов: {str(e)}", "danger")
        return redirect(url_for('port_scanning'))

@app.route('/security-headers', methods=['GET', 'POST'])
def security_headers():
    form = SecurityHeadersForm()
    if form.validate_on_submit():
        if 'delete' in request.form:
            url = request.form.get('url')
            if db_manager.delete_security_headers(url):
                flash(f"Проверка заголовков для {url} удалена.", "success")
                return redirect(url_for('security_headers', page=request.args.get('page', 1, type=int)))
            else:
                flash(f"Не удалось удалить проверку заголовков для {url}.", "danger")
                page = request.args.get('page', 1, type=int)
                per_page = 10
                total_results = len(db_manager.get_all_records('security_headers'))
                return render_template("error.html", title="Ошибка", message=f"Не удалось удалить заголовки для {url}", 
                                       page=page, total_results=total_results, per_page=per_page), 500
        else:
            url = form.url.data
            check_now = form.check_now.data
            try:
                if check_now:
                    headers_checker.check_all([url])
                flash(f"Проверка заголовков для {url} добавлена.", "success")
                return redirect(url_for('security_headers', page=request.args.get('page', 1, type=int)))
            except Exception as e:
                logger.error(f"Ошибка при добавлении заголовков для {url}: {str(e)}")
                flash(f"Ошибка при добавлении заголовков: {str(e)}", "danger")
                page = request.args.get('page', 1, type=int)
                per_page = 10
                total_results = len(db_manager.get_all_records('security_headers'))
                return render_template("error.html", title="Ошибка", message=f"Ошибка при проверке заголовков для {url}", 
                                       page=page, total_results=total_results, per_page=per_page), 500
    page = request.args.get('page', 1, type=int)
    per_page = 10
    all_results = db_manager.get_all_records('security_headers')
    total_results = len(all_results)
    results = all_results[(page - 1) * per_page: page * per_page]
    return render_template('security_headers.html', results=results, current_time=datetime.now(), form=form,
                           total_results=total_results, per_page=per_page, page=page)

@app.route('/headers-check/<path:url>')
def headers_check(url):
    try:
        headers_checker.check_all([url])
        flash(f"Заголовки для {url} проверены.", "success")
        return redirect(url_for('security_headers'))
    except Exception as e:
        logger.error(f"Ошибка при проверке заголовков для {url}: {str(e)}")
        flash(f"Ошибка при проверке заголовков: {str(e)}", "danger")
        return redirect(url_for('security_headers'))

@app.route('/tasks', methods=['GET', 'POST'])
def scheduler_tasks():
    form = TaskForm()
    if form.validate_on_submit():
        task_name = form.task_name.data
        function_name = form.function.data
        interval = form.interval.data
        try:
            function = TASK_FUNCTIONS.get(function_name)
            if not function:
                flash(f"Неизвестная функция: {function_name}. Доступные: {', '.join(TASK_FUNCTIONS.keys())}", "danger")
                return redirect(url_for('scheduler_tasks'))
            scheduler.add_task(task_name, function, interval, 'minutes')
            flash(f"Задача {task_name} добавлена.", "success")
            return redirect(url_for('scheduler_tasks'))
        except Exception as e:
            logger.error(f"Ошибка при добавлении задачи {task_name}: {str(e)}")
            flash(f"Ошибка при добавлении задачи: {str(e)}", "danger")
            return redirect(url_for('scheduler_tasks'))
    tasks = scheduler.get_task_info()
    return render_template('tasks.html', tasks=tasks, scheduler_running=scheduler.is_running(), 
                           current_time=datetime.now(), form=form)

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
            scheduler.stop()
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)})

@app.route('/alerts')
def alerts():
    alerts_list = []  # Заменить на реальные данные позже
    return render_template('alerts.html', alerts=alerts_list, current_time=datetime.now())

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