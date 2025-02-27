# modules/port_scanner.py
import socket
import threading
from queue import Queue
from typing import List, Dict, Any
import time
import logging
import config

logger = logging.getLogger("PortScanner")

class PortScanner:
    def __init__(self, db, notifier, config_obj):
        self.db = db
        self.notifier = notifier
        self.config = config_obj  # Добавляем config как атрибут
        self.enabled = self.config.PORT_SCAN_ENABLED
        self.timeout = self.config.PORT_SCAN_TIMEOUT
        self.threads = self.config.PORT_SCAN_THREADS  # Используем из config
        self.queue = Queue()
        self.lock = threading.Lock()
        self.results = []  # Инициализируем results здесь

    def _scan_port(self, ip: str, port: int) -> Dict[str, Any]:
        state = "closed"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                state = "open"
            sock.close()
        except Exception as e:
            logger.error(f"Ошибка сканирования порта {port} на {ip}: {str(e)}")
        return {"port": port, "state": state}

    def _worker(self, ip: str):
        while not self.queue.empty():
            port = self.queue.get()
            result = self._scan_port(ip, port)
            with self.lock:
                self.results.append(result)
                previous_state = self.db.get_last_port_scan(ip)
                if previous_state and self._detect_change(previous_state, result):
                    self._notify_change(ip, result)
            self.queue.task_done()

    def _detect_change(self, previous: Dict[str, Any], current: Dict[str, Any]) -> bool:
        prev_ports = {p["port"]: p["state"] for p in previous.get("ports", [])}
        curr_port = current["port"]
        curr_state = current["state"]
        prev_state = prev_ports.get(curr_port)
        return prev_state != curr_state and prev_state is not None

    def _notify_change(self, ip: str, result: Dict[str, Any]) -> None:
        port = result["port"]
        state = result["state"]
        title = f"ℹ️ Изменение состояния порта {port} на {ip}"
        message = f"Порт {port} на {ip} теперь {'открыт' if state == 'open' else 'закрыт'}."
        self.notifier.send_notification(title, message, priority="high")

    def scan(self, ip: str, ports: List[str]) -> List[Dict[str, Any]]:
        if not self.enabled:
            logger.info("Сканирование портов отключено")
            return []
        logger.info(f"Сканирование портов для {ip}")
        self.results = []  # Сбрасываем результаты перед сканированием
        threads = []
        ports_to_scan = [int(p) for p in ports if p.strip().isdigit()]
        if not ports_to_scan:
            logger.warning(f"Нет валидных портов для сканирования {ip}")
            return []

        # Заполняем очередь портами
        for port in ports_to_scan:
            self.queue.put(port)

        # Запускаем потоки
        num_threads = min(self.threads, len(ports_to_scan))
        for _ in range(num_threads):
            t = threading.Thread(target=self._worker, args=(ip,), daemon=True)
            t.start()
            threads.append(t)

        # Ждем завершения сканирования
        self.queue.join()
        for t in threads:
            t.join()

        if self.results:
            self.db.save_port_scan({"ip": ip, "ports": self.results, "timestamp": time.time()})
        changes = [r for r in self.results if self._detect_change(self.db.get_last_port_scan(ip) or {}, r)]
        return changes