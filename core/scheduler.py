# core/scheduler.py
import logging
import threading
import time
from typing import Callable, Dict, Any

logger = logging.getLogger(__name__)

class Scheduler:
    def __init__(self):
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self.running = False
        self.lock = threading.Lock()  # Добавляем lock

    def add_task(self, name: str, function: Callable[[], None], interval: int, interval_type: str) -> None:
        if interval_type not in ["seconds", "minutes", "hours"]:
            raise ValueError(f"Недопустимый тип интервала: {interval_type}. Доступные: seconds, minutes, hours")
        
        interval_seconds = interval
        if interval_type == "minutes":
            interval_seconds *= 60
        elif interval_type == "hours":
            interval_seconds *= 3600

        with self.lock:
            if name in self.tasks:
                logger.warning(f"Задача '{name}' уже существует и будет перезаписана")
            self.tasks[name] = {
                "function": function,
                "interval": interval_seconds,
                "interval_type": interval_type,
                "last_run": None,
                "thread": None,
                "active": True
            }
        logger.info(f"Задача '{name}' добавлена в планировщик (интервал: {interval} {interval_type})")

    def _run_task(self, name: str) -> None:
        while self.running and self.tasks[name]["active"]:
            with self.lock:
                task = self.tasks[name]
                if not task["active"]:
                    break
            try:
                task["function"]()
                with self.lock:
                    task["last_run"] = time.time()
            except Exception as e:
                logger.error(f"Ошибка при выполнении задачи '{name}': {str(e)}")
            time.sleep(task["interval"])

    def start(self) -> None:
        with self.lock:
            if self.running:
                logger.warning("Планировщик уже запущен")
                return
            self.running = True
            for name in self.tasks:
                if not self.tasks[name]["thread"]:
                    thread = threading.Thread(target=self._run_task, args=(name,), daemon=True)
                    self.tasks[name]["thread"] = thread
                    thread.start()
        logger.info("Планировщик задач запущен")

    def stop(self) -> None:
        with self.lock:
            self.running = False
            for task in self.tasks.values():
                task["active"] = False
        logger.info("Планировщик задач остановлен")

    def pause_task(self, name: str) -> None:
        with self.lock:
            if name in self.tasks:
                self.tasks[name]["active"] = False
                logger.info(f"Задача '{name}' приостановлена")
            else:
                logger.warning(f"Задача '{name}' не найдена")

    def resume_task(self, name: str) -> None:
        with self.lock:
            if name in self.tasks:
                if not self.tasks[name]["active"]:
                    self.tasks[name]["active"] = True
                    if not self.tasks[name]["thread"] or not self.tasks[name]["thread"].is_alive():
                        thread = threading.Thread(target=self._run_task, args=(name,), daemon=True)
                        self.tasks[name]["thread"] = thread
                        thread.start()
                    logger.info(f"Задача '{name}' возобновлена")
            else:
                logger.warning(f"Задача '{name}' не найдена")

    def remove_task(self, name: str) -> None:
        with self.lock:
            if name in self.tasks:
                self.tasks[name]["active"] = False
                del self.tasks[name]
                logger.info(f"Задача '{name}' удалена")
            else:
                logger.warning(f"Задача '{name}' не найдена")

    def get_task_info(self) -> Dict[str, Dict[str, Any]]:
        with self.lock:
            return {
                name: {
                    "function": task["function"].__name__,
                    "interval": task["interval"],
                    "interval_type": task["interval_type"],
                    "last_run": task["last_run"],
                    "is_active": task["active"]
                }
                for name, task in self.tasks.items()
            }

    def is_running(self) -> bool:
        with self.lock:
            return self.running