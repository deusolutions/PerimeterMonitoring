import logging
import time
import schedule
import threading
from typing import Callable, Dict, Any, List
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Scheduler:
    def __init__(self):
        self._stop_event = threading.Event()
        self._thread = None
        self._tasks = {}

    def add_task(self, name: str, func: Callable, interval: int, interval_type: str = 'minutes', **kwargs) -> bool:
        if self.is_running():
            logger.error("Нельзя добавлять задачи после запуска планировщика.")
            return False
        if not isinstance(interval, int) or interval <= 0:
            logger.error(f"Некорректный интервал: {interval}")
            return False
        if name in self._tasks:
            logger.warning(f"Задача с именем '{name}' уже существует")
            return False

        def task_wrapper():
            try:
                logger.info(f"Выполнение задачи '{name}'")
                start_time = time.time()
                result = func()
                execution_time = time.time() - start_time
                logger.info(f"Задача '{name}' выполнена за {execution_time:.2f} сек")
                self._tasks[name]['last_run'] = datetime.now()
                self._tasks[name]['last_execution_time'] = execution_time
            except Exception as e:
                logger.error(f"Ошибка при выполнении задачи '{name}': {str(e)}")
                self._tasks[name]['last_error'] = str(e)  # Сохраняем ошибку

        job = None
        if interval_type == 'seconds':
            job = schedule.every(interval).seconds.do(task_wrapper)
        elif interval_type == 'minutes':
            job = schedule.every(interval).minutes.do(task_wrapper)
        elif interval_type == 'hours':
            job = schedule.every(interval).hours.do(task_wrapper)
        elif interval_type == 'days':
            job = schedule.every(interval).days.do(task_wrapper)
        else:
            logger.error(f"Неизвестный тип интервала: {interval_type}")
            return False

        self._tasks[name] = {
            'job': job,
            'function': func.__name__,
            'interval': interval,
            'interval_type': interval_type,
            'added_at': datetime.now(),
            'last_run': None,
            'last_execution_time': None,
            'last_error': None,
            'is_active': True,
            'func': func
        }

        logger.info(f"Задача '{name}' добавлена в планировщик (интервал: {interval} {interval_type})")
        return True

    def remove_task(self, name: str) -> bool:
        if name not in self._tasks:
            logger.warning(f"Задача с именем '{name}' не найдена")
            return False

        schedule.cancel_job(self._tasks[name]['job'])
        del self._tasks[name]
        logger.info(f"Задача '{name}' удалена из планировщика")
        return True

    def pause_task(self, name: str) -> bool:
        if name not in self._tasks:
            logger.warning(f"Задача с именем '{name}' не найдена")
            return False

        if self._tasks[name]['is_active']:
            schedule.cancel_job(self._tasks[name]['job'])
            self._tasks[name]['is_active'] = False
            logger.info(f"Задача '{name}' приостановлена")
        return True

    def resume_task(self, name: str) -> bool:
        if name not in self._tasks:
            logger.warning(f"Задача с именем '{name}' не найдена")
            return False

        if not self._tasks[name]['is_active']:
            interval = self._tasks[name]['interval']
            interval_type = self._tasks[name]['interval_type']
            func = self._tasks[name]['func']

            def task_wrapper():
                try:
                    logger.info(f"Выполнение задачи '{name}'")
                    start_time = time.time()
                    result = func()
                    execution_time = time.time() - start_time
                    logger.info(f"Задача '{name}' выполнена за {execution_time:.2f} сек")
                    self._tasks[name]['last_run'] = datetime.now()
                    self._tasks[name]['last_execution_time'] = execution_time
                except Exception as e:
                    logger.error(f"Ошибка при выполнении задачи '{name}': {str(e)}")
                    self._tasks[name]['last_error'] = str(e)

            if interval_type == 'seconds':
                job = schedule.every(interval).seconds.do(task_wrapper)
            elif interval_type == 'minutes':
                job = schedule.every(interval).minutes.do(task_wrapper)
            elif interval_type == 'hours':
                job = schedule.every(interval).hours.do(task_wrapper)
            elif interval_type == 'days':
                job = schedule.every(interval).days.do(task_wrapper)
            self._tasks[name]['job'] = job
            self._tasks[name]['is_active'] = True
            logger.info(f"Задача '{name}' возобновлена")
        return True

    def get_task_info(self) -> Dict[str, Dict[str, Any]]:
        with self.lock:
            return {
                name: {
                    "function": task["function"].__name__,
                    "interval": task["interval"],
                    "interval_type": task["interval_type"],
                    "last_run": task["last_run"],
                    "is_active": not task["thread"].daemon or task["thread"].is_alive()
                }
                for name, task in self.tasks.items()
            }

        result = {}
        for task_name, task_info in self._tasks.items():
            task_copy = task_info.copy()
            if 'job' in task_copy:
                del task_copy['job']
            if 'func' in task_copy:
                del task_copy['func']
            result[task_name] = task_copy
        return result

    def start(self):
        if self._thread is not None and self._thread.is_alive():
            logger.warning("Планировщик уже запущен")
            return

        self._stop_event.clear()

        def run():  # Добавлено двоеточие
            logger.info("Планировщик задач запущен")
            while not self._stop_event.is_set():
                schedule.run_pending()
                time.sleep(1)
            logger.info("Планировщик задач остановлен")

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def stop(self):
        if self._thread is None or not self._thread.is_alive():
            logger.warning("Планировщик не запущен")
            return

        logger.info("Остановка планировщика задач...")
        self._stop_event.set()
        self._thread.join(timeout=5)
        if self._thread.is_alive():
            logger.warning("Планировщик не остановился корректно")
        else:
            logger.info("Планировщик задач остановлен")
            self._thread = None

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()