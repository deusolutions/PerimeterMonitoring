from dashboard.app import app, db_manager  # Импортируем db_manager из app.py
from main import PerimeterMonitor

def run_monitor():
    monitor = PerimeterMonitor(db_manager)  # Передаем db_manager
    monitor.run()

if __name__ == "__main__":
    import threading
    t = threading.Thread(target=run_monitor, daemon=True)
    t.start()
    app.run(host='0.0.0.0', port=5000, debug=False)