
import threading
from main import PerimeterMonitor
from dashboard.app import app
import logging

def run_monitor():
    monitor = PerimeterMonitor()
    monitor.run()

def run_dashboard():
    app.run(host='0.0.0.0', port=5000)

if __name__ == "__main__":
    # Настройка логирования
    logging.basicConfig(level=logging.INFO)
    
    # Запуск мониторинга в отдельном потоке
    monitor_thread = threading.Thread(target=run_monitor)
    monitor_thread.daemon = True
    monitor_thread.start()
    
    # Запуск веб-панели в основном потоке
    run_dashboard()
