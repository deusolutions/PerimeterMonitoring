# init.py
import logging
from core.database import Database
from main import PerimeterMonitor

# Настройка логирования (если ещё не настроено в другом месте)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

db_manager = Database()
db_manager.initialize()  # Сразу инициализируем БД
monitor = PerimeterMonitor(db_manager)