# run.py
from dashboard.app import app
from init import monitor, db_manager  # Импортируем из init.py


def run_monitor():
    # monitor = PerimeterMonitor(db_manager)  # УДАЛЯЕМ
    monitor.run()


if __name__ == "__main__":
    import threading

    t = threading.Thread(target=run_monitor, daemon=True)
    t.start()
    app.run(host='0.0.0.0', port=5000, debug=False)