# modules/ip_scanner.py
import ipaddress
import logging
from typing import List, Dict, Any
import time
import socket
import config

logger = logging.getLogger("IPScanner")

class IPScanner:
    def __init__(self, db, notifier):
        self.db = db
        self.notifier = notifier
        self.ip_ranges = config.IP_RANGES
        self.timeout = config.IP_SCAN_TIMEOUT
        logger.debug(f"IP ranges from config: {self.ip_ranges}")

    def _expand_ip_ranges(self) -> List[str]:
        all_ips = []
        for ip_range in self.ip_ranges:
            ip_range = ip_range.strip()
            logger.debug(f"Processing IP range: {ip_range}")
            try:
                if "/" in ip_range:
                    network = ipaddress.ip_network(ip_range, strict=False)
                    all_ips.extend([str(ip) for ip in network.hosts()])
                elif "-" in ip_range:
                    start_ip, end_ip = ip_range.split("-", 1)  # Ограничиваем разделение до первого "-"
                    start = ipaddress.ip_address(start_ip.strip())
                    end = ipaddress.ip_address(end_ip.strip())
                    if start > end:
                        logger.error(f"Некорректный диапазон: {ip_range}. Начальный IP больше конечного.")
                        continue
                    for ip_int in range(int(start), int(end) + 1):
                        all_ips.append(str(ipaddress.ip_address(ip_int)))
                else:
                    all_ips.append(ip_range)
            except Exception as e:
                logger.error(f"Ошибка при обработке диапазона IP {ip_range}: {str(e)}")
        logger.info(f"Всего IP-адресов для сканирования: {len(all_ips)}")
        logger.debug(f"Expanded IPs: {all_ips[:5]}...")  # Первые 5 для отладки
        return all_ips

    def _ping_ip(self, ip: str) -> Dict[str, Any]:
        try:
            start_time = time.time()
            socket.setdefaulttimeout(self.timeout)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((ip, 80))  # Проверка порта 80 как индикатор доступности
            sock.close()
            is_up = result == 0
            hostname = socket.gethostbyaddr(ip)[0] if is_up else None
            response_time = (time.time() - start_time) * 1000 if is_up else None  # В миллисекундах
        except (socket.timeout, socket.error, socket.herror):
            is_up = False
            hostname = None
            response_time = None
        return {
            "ip_address": ip,
            "is_up": is_up,
            "hostname": hostname,
            "response_time": response_time,
            "description": None,
            "scan_time": time.time()
        }

    def _detect_change(self, previous: Dict[str, Any], current: Dict[str, Any]) -> bool:
        return (previous.get("is_up") != current["is_up"] or 
                previous.get("hostname") != current["hostname"])

    def _notify_change(self, change: Dict[str, Any]) -> None:
        ip = change["ip_address"]
        old_state = self.db.get_ip_state(ip) or {"is_up": False, "hostname": None}
        new_state = {"is_up": change["is_up"], "hostname": change["hostname"]}
        if old_state["is_up"] != new_state["is_up"]:
            if new_state["is_up"]:
                title = f"🟢 IP {ip} стал доступен"
                message = f"IP-адрес {ip} снова отвечает на пинги.\n"
                if new_state["hostname"]:
                    message += f"Определенное имя хоста: {new_state['hostname']}"
            else:
                title = f"🔴 IP {ip} стал недоступен"
                message = f"IP-адрес {ip} перестал отвечать на пинги.\n"
                message += f"Предыдущее имя хоста: {old_state['hostname']}"
            self.notifier.send_notification(title, message, priority="normal")

    def scan(self, ips: List[str] = None) -> List[Dict[str, Any]]:
        all_ips = ips if ips is not None else self._expand_ip_ranges()
        logger.info(f"Запуск сканирования {len(all_ips)} IP-адресов")
        changes = []
        for ip in all_ips:
            current_state = self._ping_ip(ip)
            previous_state = self.db.get_ip_state(ip)
            if previous_state and self._detect_change(previous_state, current_state):
                changes.append({"ip_address": ip, "old_state": previous_state, "new_state": current_state})
                self._notify_change(current_state)
            try:
                self.db.save_ip_state(current_state)
            except Exception as e:
                logger.error(f"Ошибка при сохранении изменения IP {ip}: {str(e)}")
        logger.info(f"Сканирование завершено. Обнаружено {len(changes)} изменений.")
        return changes