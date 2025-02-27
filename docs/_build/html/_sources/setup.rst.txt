.. _setup:

Установка и настройка
=====================

Требования
----------
- Python 3.8+
- SQLite (встроен в Python)
- Зависимости из ``requirements.txt``

Установка
---------
1. Склонируйте репозиторий:
   .. code-block:: bash

      git clone https:/github.com/deusolutions/PerimeterMonitoring
      cd PerimeterMonitoring

2. Установите зависимости:
   .. code-block:: bash

      pip install -r requirements.txt

3. Настройте переменные окружения в ``.env`` (пример):
   .. code-block:: bash

      DB_NAME=monitoring.db
      FLASK_SECRET_KEY=your-secret-key-here
      IP_RANGES=192.168.1.1-192.168.1.10
      WEBSITES=https://example.com,https://another.com
      TELEGRAM_TOKEN=your-telegram-token  # Опционально
      TELEGRAM_CHAT_ID=your-chat-id      # Опционально

Запуск
------
1. Запустите приложение:
   .. code-block:: bash

      python run.py

2. Откройте браузер по адресу ``http://localhost:5000``.

База данных создается автоматически при первом запуске.