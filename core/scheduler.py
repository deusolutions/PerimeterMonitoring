import logging
import time
import schedule
import threading
from typing import Callable, Dict, Any, List
from datetime import datetime

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Scheduler:
    """
    Модуль для планирования и выполнения периодических задач мониторинга.
    Использует библиотеку schedule для управления заданиями.
    """
    
    def __init__(self):
        """
        Инициализация планировщика задач
        """
        self._stop_event = threading.Event()
        self._thread = None
        self._tasks = {}  # Словарь для хранения информации о задачах
    
    def add_task(self, name: str, func: Callable, interval: int, interval_type: str = 'minutes', **kwargs) -> bool:
        """
        Добавляет новую задачу в планировщик
        
        :param name: уникальное имя задачи
        :param func: функция для выполнения
        :param interval: числовое значение интервала
        :param interval_type: тип интервала (seconds, minutes, hours, days)
        :param kwargs: дополнительные аргументы для передачи в функцию
        :return: успех операции
        """
        if name in self._tasks:
            logger.warning(f"Задача с именем '{name}' уже существует")
            return False
        
        # Создаем обертку для функции, чтобы передать ей аргументы
        def task_wrapper():
            try:
                logger.info(f"Выполнение задачи '{name}'")
                start_time = time.time()
                result = func(**kwargs)
                execution_time = time.time() - start_time
                logger.info(f"Задача '{name}' выполнена за {execution_time:.2f} сек")
                
                # Обновляем информацию о последнем выполнении
                self._tasks[name]['last_run'] = datetime.now()
                self._tasks[name]['last_execution_time'] = execution_time
                
                return result
            except Exception as e:
                logger.error(f"Ошибка при выполнении задачи '{name}': {str(e)}")
                self._tasks[name]['last_error'] = str(e)
        
        # Создаем задачу в планировщике в зависимости от типа интервала
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
        
        # Сохраняем информацию о задаче
        self._tasks[name] = {
            'job': job,
            'function': func.__name__,
            'interval': interval,
            'interval_type': interval_type,
            'added_at': datetime.now(),
            'last_run': None,
            'last_execution_time': None,
            'last_error': None,
            'is_active': True
        }
        
        logger.info(f"Задача '{name}' добавлена в планировщик (интервал: {interval} {interval_type})")
        return True
    
    def remove_task(self, name: str) -> bool:
        """
        Удаляет задачу из планировщика
        
        :param name: имя задачи для удаления
        :return: успех операции
        """
        if name not in self._tasks:
            logger.warning(f"Задача с именем '{name}' не найдена")
            return False
        
        # Отменяем задачу в планировщике
        schedule.cancel_job(self._tasks[name]['job'])
        del self._tasks[name]
        
        logger.info(f"Задача '{name}' удалена из планировщика")
        return True
    
    def pause_task(self, name: str) -> bool:
        """
        Приостанавливает выполнение задачи
        
        :param name: имя задачи
        :return: успех операции
        """
        if name not in self._tasks:
            logger.warning(f"Задача с именем '{name}' не найдена")
            return False
        
        # Отменяем задачу, но сохраняем информацию о ней
        if self._tasks[name]['is_active']:
            schedule.cancel_job(self._tasks[name]['job'])
            self._tasks[name]['is_active'] = False
            logger.info(f"Задача '{name}' приостановлена")
        
        return True
    
    def resume_task(self, name: str) -> bool:
        """
        Возобновляет выполнение задачи
        
        :param name: имя задачи
        :return: успех операции
        """
        if name not in self._tasks:
            logger.warning(f"Задача с именем '{name}' не найдена")
            return False
        
        # Если задача не активна, добавляем ее снова в планировщик
        if not self._tasks[name]['is_active']:
            # Здесь нужно воссоздать задачу на основе сохраненной информации
            # Это упрощенная версия, в реальном проекте может потребоваться более сложная логика
            func_name = self._tasks[name]['function']
            interval = self._tasks[name]['interval']
            interval_type = self._tasks[name]['interval_type']
            
            # Поскольку у нас нет прямого доступа к функции, это демонстрационная логика
            # В реальном проекте нужно сохранять ссылку на функцию или использовать другой подход
            logger.warning(f"Возобновление задачи '{name}' требует реализации в конкретном проекте")
            self._tasks[name]['is_active'] = True
            
            logger.info(f"Задача '{name}' возобновлена")
        
        return True
    
    def get_task_info(self, name: str = None) -> Dict[str, Any]:
        """
        Возвращает информацию о задаче или всех задачах
        
        :param name: имя задачи (если None, возвращает информацию обо всех задачах)
        :return: информация о задаче/задачах
        """
        if name is not None:
            if name not in self._tasks:
                logger.warning(f"Задача с именем '{name}' не найдена")
                return {}
            
            # Возвращаем копию информации о задаче без объекта job
            task_info = self._tasks[name].copy()
            if 'job' in task_info:
                del task_info['job']
            return task_info
        
        # Возвращаем информацию обо всех задачах
        result = {}
        for task_name, task_info in self._tasks.items():
            task_copy = task_info.copy()
            if 'job' in task_copy:
                del task_copy['job']
            result[task_name] = task_copy
        
        return result
    
    def start(self):
        """
        Запускает планировщик в отдельном потоке
        """
        if self._thread is not None and self._thread.is_alive():
            logger.warning("Планировщик уже запущен")
            return
        
        self._stop_event.clear()
        
        def run():
            logger.info("Планировщик задач запущен")
            while not self._stop_event.is_set():
                schedule.run_pending()
                time.sleep(1)
            logger.info("Планировщик задач остановлен")
        
        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
    
    def stop(self):
        """
        Останавливает планировщик
        """
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
        """
        Проверяет, запущен ли планировщик
        
        :return: True, если планировщик запущен, иначе False
        """
        return self._thread is not None and self._thread.is_alive()