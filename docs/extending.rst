.. _extending:

Расширение и доработка
======================

Добавление уведомлений
----------------------
- В ``core/notification.py`` реализуйте отправку в Telegram/Slack:
  .. code-block:: python

     def send_notification(self, title: str, message: str, priority: str = "normal"):
         logger.info(f"Уведомление [{priority}]: {title} - {message}")
         # Добавьте код для Telegram или Slack

Новые модули мониторинга
------------------------
1. Создайте новый файл в ``modules/`` (например, ``new_monitor.py``).
2. Реализуйте класс с методами ``check_all`` и уведомлениями.
3. Добавьте его в ``main.py`` в ``PerimeterMonitor``.

Кастомные стили
---------------
- Редактируйте ``static/css/style.css`` для изменения внешнего вида.

Логирование
-----------
- Настройте уровень логирования в ``logging.basicConfig`` (например, ``DEBUG``).