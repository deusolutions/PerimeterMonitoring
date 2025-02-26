from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
import logging
import os
import sys
from datetime import datetime

# Добавляем родительский каталог в sys.path для импорта модулей проекта
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import Database
from core.scheduler import Scheduler
import config

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = config.FLASK_SECRET_KEY

# Инициализация компонентов
db_manager = Database()
db_manager.initialize()
scheduler = None  # Будет инициализирован в before_first_request

@app.before_request
def initialize():
    """Инициализация перед первым запросом"""
    global scheduler
    scheduler = Scheduler()
    # Здесь можно добавить инициализацию других компонентов, если необходимо

@app.route('/')
def index():
    """Главная страница дашборда"""
    return render_template('index.html', 
                          title='Мониторинг периметра',
                          current_time=datetime.now())

@app.route('/ip-scan')
def ip_scan():
    """Страница результатов сканирования IP"""
    # Получаем данные из БД
    ip_scan_results = db_manager.get_all_records('ip_scan_results', limit=100)
    return render_template('ip_scan.html', 
                          title='Результаты сканирования IP',
                          results=ip_scan_results,
                          current_time=datetime.now())

@app.route('/websites')
def websites():
    """Страница мониторинга веб-сайтов"""
    # Получаем данные из БД
    website_results = db_manager.get_all_records('website_monitoring', limit=100)
    return render_template('websites.html', 
                          title='Мониторинг веб-сайтов',
                          results=website_results,
                          current_time=datetime.now())

@app.route('/certificates')
def certificates():
    """Страница мониторинга SSL-сертификатов"""
    # Получаем данные из БД
    cert_results = db_manager.get_all_records('ssl_certificates', limit=100)
    return render_template('certificates.html', 
                          title='Мониторинг SSL-сертификатов',
                          results=cert_results,
                          current_time=datetime.now())

@app.route('/dns')
def dns_monitoring():
    """Страница мониторинга DNS"""
    # Получаем данные из БД
    dns_results = db_manager.get_all_records('dns_monitoring', limit=100)
    return render_template('dns.html', 
                          title='Мониторинг DNS',
                          results=dns_results,
                          current_time=datetime.now())

@app.route('/ports')
def port_scanning():
    """Страница сканирования портов"""
    # Получаем данные из БД
    port_results = db_manager.get_all_records('port_scanning', limit=100)
    return render_template('ports.html', 
                          title='Сканирование портов',
                          results=port_results,
                          current_time=datetime.now())

@app.route('/security-headers')
def security_headers():
    """Страница проверки заголовков безопасности"""
    # Получаем данные из БД
    headers_results = db_manager.get_all_records('security_headers', limit=100)
    return render_template('security_headers.html', 
                          title='Заголовки безопасности',
                          results=headers_results,
                          current_time=datetime.now())

@app.route('/tasks')
def scheduler_tasks():
    """Страница управления задачами планировщика"""
    if scheduler is None:
        return render_template('error.html', message="Планировщик не инициализирован")
    
    tasks = scheduler.get_task_info()
    return render_template('tasks.html', 
                          title='Управление задачами',
                          tasks=tasks,
                          scheduler_running=scheduler.is_running(),
                          current_time=datetime.now())

@app.route('/api/tasks', methods=['GET'])
def api_get_tasks():
    """API для получения информации о задачах"""
    if scheduler is None:
        return jsonify({"error": "Планировщик не инициализирован"}), 500
    
    tasks = scheduler.get_task_info()
    return jsonify({"tasks": tasks})

@app.route('/api/tasks/control', methods=['POST'])
def api_control_task():
    """API для управления задачами (пауза/возобновление/удаление)"""
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
    """API для управления планировщиком (старт/стоп)"""
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
    """API для получения данных из таблиц"""
    # Проверяем, что запрошенная таблица допустима
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

# Обработчик ошибок для 404
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', title='Страница не найдена',
                          message='Запрошенная страница не существует',
                          current_time=datetime.now()), 404

# Обработчик ошибок для 500
@app.errorhandler(500)
def internal_error(e):
    return render_template('error.html', title='Внутренняя ошибка сервера',
                          message='Произошла внутренняя ошибка сервера. Пожалуйста, попробуйте позже.',
                          current_time=datetime.now()), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Запускаем веб-сервер
    app.run(host='0.0.0.0', port=port, debug=debug)