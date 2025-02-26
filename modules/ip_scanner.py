"""
Модуль сканирования IP-адресов и обнаружения изменений
"""
import logging
import socket
import subprocess
import platform
import ipaddress
from datetime import datetime
from typing import List, Dict, Any

import config
from core.database import Database
from core.notification import NotificationManager

logger = logging.getLogger("IPScanner")

class IPScanner:
    """Класс для сканирования IP-адресов и обнаружения изменений"""
    
    def __init__(self, db: Database, notifier: NotificationManager):
        self.db = db
        self.notifier = notifier
        self.timeout = config.IP_SCAN_TIMEOUT
        self.ip_ranges = config.IP_RANGES
    
    def _ping(self, ip_address: str) -> bool:
        """
        Проверка доступности IP-адреса с помощью ICMP ping
        
        Args:
            ip_address: IP-адрес для проверки
            
        Returns:
            bool: True, если хост отвечает, иначе False
        """
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-W', str(self.timeout), ip_address]
        
        try:
            return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
        except Exception as e:
            logger.error(f"Ошибка при выполнении ping до {ip_address}: {str(e)}")
            return False
    
    def _get_hostname(self, ip_address: str) -> str:
        """
        Получение имени хоста по IP-адресу
        
        Args:
            ip_address: IP-адрес
            
        Returns:
            str: Имя хоста или пустая строка, если невозможно определить
        """
        try:
            return socket.getfqdn(ip_address)
        except Exception as e:
            logger.debug(f"Невозможно получить имя хоста для {ip_address}: {str(e)}")
            return ""
    
    def _scan_single_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Сканирование отдельного IP-адреса
        
        Args:
            ip_address: IP-адрес для сканирования
            
        Returns:
            Dict: Информация о состоянии IP-адреса
        """
        is_up = self._ping(ip_address)
        hostname = self._get_hostname(ip_address) if is_up else ""
        
        return {
            "ip_address": ip_address,
            "is_up": is_up,
            "hostname": hostname,
            "scan_time": datetime.now()
        }
    
    def _expand_ip_ranges(self) -> List[str]:
        """
        Преобразование диапазонов IP в список отдельных IP-адресов
        
        Returns:
            List[str]: Список IP-адресов
        """
        all_ips = []
        
        for ip_range in self.ip_ranges:
            ip_range = ip_range.strip()
            if not ip_range:
                continue
                
            try:
                # Поддержка формата CIDR (например, 192.168.1.0/24)
                if "/" in ip_range:
                    network = ipaddress.ip_network(ip_range, strict=False)
                    all_ips.extend([str(ip) for ip in network.hosts()])
                # Поддержка диапазона через дефис (например, 192.168.1.1-192.168.1.10)
                elif "-" in ip_range:
                    start_ip, end_ip = ip_range.split("-")
                    start_ip = ipaddress.IPv4Address(start_ip.strip())
                    end_ip = ipaddress.IPv4Address(end_ip.strip())
                    all_ips.extend([str(ipaddress.IPv4Address(ip)) for ip in range(int(start_ip), int(end_ip) + 1)])
                # Поддержка одиночного IP-адреса
                else:
                    all_ips.append(ip_range)
            except Exception as e:
                logger.error(f"Ошибка при обработке диапазона IP {ip_range}: {str(e)}")
        
        return all_ips
    
    def scan(self) -> List[Dict[str, Any]]:
        """
        Сканирование всех IP-адресов и обнаружение изменений
        
        Returns:
            List[Dict]: Список изменений
        """
        results = []
        changes = []
        ip_addresses = self._expand_ip_ranges()
        
        logger.info(f"Запуск сканирования {len(ip_addresses)} IP-адресов")
        
        for ip in ip_addresses:
            try:
                scan_result = self._scan_single_ip(ip)
                results.append(scan_result)
                
                # Получение предыдущего состояния из базы данных
                previous_state = self.db.get_ip_state(ip)
                
                # Если это первое сканирование
                if previous_state is None:
                    self.db.save_ip_state(scan_result)
                    continue
                
                # Проверка наличия изменений
                if (previous_state["is_up"] != scan_result["is_up"] or
                    previous_state["hostname"] != scan_result["hostname"]):
                    
                    change = {
                        "ip_address": ip,
                        "old_state": previous_state,
                        "new_state": scan_result,
                        "change_time": datetime.now()
                    }
                    
                    changes.append(change)
                    
                    # Сохранение изменения в БД
                    self.db.save_ip_change(change)
                    
                    # Обновление текущего состояния
                    self.db.save_ip_state(scan_result)
                    
                    # Отправка уведомления об изменении
                    self._notify_change(change)
            
            except Exception as e:
                logger.error(f"Ошибка при сканировании IP {ip}: {str(e)}")
        
        logger.info(f"Сканирование завершено. Обнаружено {len(changes)} изменений.")
        return changes
    
    def _notify_change(self, change: Dict[str, Any]) -> None:
        """
        Отправка уведомления об изменении состояния IP
        
        Args:
            change: Информация об изменении
        """
        ip = change["ip_address"]
        old_state = change["old_state"]
        new_state = change["new_state"]
        
        # Формирование сообщения
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
            return  # Нет изменений, уведомление не требуется
        
        # Отправка уведомления
        self.notifier.send_notification(title, message)