import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

from core.database import Database
from core.notification import NotificationManager
import time

logger = logging.getLogger("PortScanner")

class PortScanner:
    def __init__(self, db: Database, notifier: NotificationManager, config):
        self.db = db
        self.notifier = notifier
        self.enabled = config.PORT_SCAN_ENABLED
        self.timeout = config.PORT_SCAN_TIMEOUT
        self.threads = config.PORT_SCAN_THREADS
        try:
            self.common_ports = config.COMMON_PORTS
        except AttributeError:
            logger.error("Ошибка при загрузке списка портов")
            self.common_ports = [80, 443]  # Значения по умолчанию
    
    def scan(self, ip: str, ports: List[str]) -> List[Dict[str, Any]]:
        if not self.enabled:
            logger.info("Сканирование портов отключено")
            return []
        logger.info(f"Сканирование портов для {ip}")
        results = []
        changes = []
        try:
            ports_to_scan = [int(p.strip()) for p in ports if p.strip().isdigit()]
            if not ports_to_scan:
                logger.warning(f"Нет валидных портов для сканирования {ip}")
                return []
            for port in ports_to_scan:
                result = self._scan_port(ip, port)
                results.append(result)
                previous_state = self.db.get_last_port_scan(ip)
                if previous_state and self._detect_change(previous_state, result):
                    changes.append(result)
                    self.db.save_port_scan({"ip": ip, "ports": [result], "timestamp": time.time()})
                    self._notify_change(ip, result)
            if results:
                self.db.save_port_scan({"ip": ip, "ports": results, "timestamp": time.time()})
            if changes:
                logger.info(f"Обнаружены изменения в портах для {ip}: {len(changes)} изменений")
            else:
                logger.info(f"Изменений в портах для {ip} не обнаружено")
            return changes
        except Exception as e:
            logger.error(f"Ошибка при сканировании портов для {ip}: {str(e)}")
            return []

    def scan_all(self) -> List[Dict[str, Any]]:
        changes = []
        ip_states = self.db.get_all_records("ip_scan_results")
        for ip_state in ip_states:
            ip = ip_state["ip_address"]
            changes.extend(self.scan(ip, [str(p) for p in self.common_ports]))
        return changes

    def _scan_port(self, ip: str, port: int) -> Dict[str, Any]:
        # Здесь должна быть реализация сканирования порта (например, с nmap или socket)
        # Для примера используем заглушку
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return {
            "port": port,
            "protocol": "tcp",
            "service": "unknown",
            "state": "open" if result == 0 else "closed"
        }

    def _detect_change(self, previous: Dict[str, Any], current: Dict[str, Any]) -> bool:
        # Простая проверка изменений (заглушка)
        return previous.get("ports", []) != current.get("ports", [])

    def _notify_change(self, ip: str, result: Dict[str, Any]) -> None:
        port = result["port"]
        state = result["state"]
        title = f"ℹ️ Изменение состояния порта {port} на {ip}"
        message = f"Порт {port} на {ip} теперь {'открыт' if state == 'open' else 'закрыт'}."
        self.notifier.send_notification(title, message)