import threading
from main import PerimeterMonitor
from dashboard.app import app

def run_monitor():
    monitor = PerimeterMonitor()
    monitor.run()

if __name__ == "__main__":
    # Запускаем мониторинг в отдельном потоке
    monitor_thread = threading.Thread(target=run_monitor, daemon=True)
    monitor_thread.start()
    
    # Запускаем Flask приложение
    app.run(host='0.0.0.0', port=5000, debug=False)