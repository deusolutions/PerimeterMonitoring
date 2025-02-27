import logging
import socket
import subprocess
import platform
import ipaddress
from datetime import datetime
from typing import List, Dict, Any, Optional

import config
from core.database import Database
from core.notification import NotificationManager

logger = logging.getLogger("IPScanner")

class IPScanner:
    def __init__(self, db: Database, notifier: NotificationManager):
        self.db = db
        self.notifier = notifier
        self.timeout = config.IP_SCAN_TIMEOUT
        self.ip_ranges = config.IP_RANGES

    def _ping(self, ip_address: str) -> bool:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-W', str(self.timeout), ip_address]
        try:
            return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
        except Exception as e:
            logger.error(f"Ошибка при выполнении ping до {ip_address}: {str(e)}")
            return False

    def _get_hostname(self, ip_address: str) -> str:
        try:
            return socket.getfqdn(ip_address)
        except Exception as e:
            logger.debug(f"Невозможно получить имя хоста для {ip_address}: {str(e)}")
            return ""

    def _scan_single_ip(self, ip_address: str) -> Dict[str, Any]:
        is_up = self._ping(ip_address)
        hostname = self._get_hostname(ip_address) if is_up else ""
        return {
            "ip_address": ip_address,
            "is_up": is_up,
            "hostname": hostname,
            "scan_time": datetime.now(),
            "description": ""  # Добавляем по умолчанию
        }

    def _expand_ip_ranges(self) -> List[str]:
        all_ips = []
        for ip_range in self.ip_ranges:
            ip_range = ip_range.strip()
            try:
                if "/" in ip_range:
                    network = ipaddress.ip_network(ip_range, strict=False)
                    all_ips.extend([str(ip) for ip in network.hosts()])  # Добавляем только хосты
                elif "-" in ip_range:
                    start_ip, end_ip = ip_range.split("-")
                    start_ip = ipaddress.IPv4Address(start_ip.strip())
                    end_ip = ipaddress.IPv4Address(end_ip.strip())

                    # Проверка на корректный диапазон
                    if start_ip > end_ip:
                        logger.error(f"Некорректный диапазон: {ip_range}. Начальный IP больше конечного.")
                        continue

                    all_ips.extend([str(ipaddress.IPv4Address(ip)) for ip in range(int(start_ip), int(end_ip) + 1)])
                else:
                    all_ips.append(ip_range)  # Добавляем как есть
            except Exception as e:
                logger.error(f"Ошибка при обработке диапазона IP {ip_range}: {str(e)}")
        return all_ips


    def scan(self, ip_list: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        if ip_list is None:
            ip_addresses = self._expand_ip_ranges()
        else:
            ip_addresses = ip_list
        results = []
        changes = []
        logger.info(f"Запуск сканирования {len(ip_addresses)} IP-адресов")
        for ip in ip_addresses:
            try:
                scan_result = self._scan_single_ip(ip)
                results.append(scan_result)
                previous_state = self.db.get_ip_state(ip)
                if previous_state is None:
                    self.db.save_ip_state(scan_result)
                    continue
                if (previous_state["is_up"] != scan_result["is_up"] or
                        previous_state["hostname"] != scan_result["hostname"]):
                    change = {
                        "ip_address": ip,
                        "old_state": previous_state,
                        "new_state": scan_result,
                        "change_time": datetime.now()
                    }
                    changes.append(change)
                    self.db.save_ip_change(change)
                    self.db.save_ip_state(scan_result)
                    self._notify_change(change)
            except Exception as e:
                logger.error(f"Ошибка при сканировании IP {ip}: {str(e)}")
        logger.info(f"Сканирование завершено. Обнаружено {len(changes)} изменений.")
        return changes

    def _notify_change(self, change: Dict[str, Any]) -> None:
        ip = change["ip_address"]
        old_state = change["old_state"]
        new_state = change["new_state"]
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
        elif old_state["hostname"] != new_state["hostname"]:
            title = f"ℹ️ Изменение имени хоста для IP {ip}"
            message = f"Для IP-адреса {ip} изменилось имя хоста.\n"
            message += f"Старое имя: {old_state['hostname']}\n"
            message += f"Новое имя: {new_state['hostname']}"
        else:
            return
        self.notifier.send_notification(title, message)