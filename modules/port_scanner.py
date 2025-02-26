#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import time
import logging
from typing import List, Dict, Any, Optional, Tuple
import json

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PortScanner:
    def __init__(self, database, config):
        self.database = database
        self.config = config
        self.timeout = getattr(config, 'PORT_SCAN_TIMEOUT', 0.5)
        self.threads = getattr(config, 'PORT_SCAN_THREADS', 50)
        self.common_ports = self._load_common_ports()
        
    def _load_common_ports(self) -> List[int]:
        try:
            return self.config.COMMON_PORTS
        except Exception as e:
            logger.error(f"Ошибка при загрузке списка портов: {e}")
            return [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
    
    def scan_port(self, ip: str, port: int) -> Dict[str, Any]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        result = {"port": port, "state": "closed", "service": "unknown", "banner": None}
        try:
            start_time = time.time()
            conn = sock.connect_ex((ip, port))
            response_time = time.time() - start_time
            if conn == 0:
                result["state"] = "open"
                result["response_time"] = round(response_time * 1000, 2)
                try:
                    service = socket.getservbyport(port)
                    result["service"] = service
                except:
                    pass
                try:
                    sock.settimeout(1)
                    banner = sock.recv(1024)
                    if banner:
                        result["banner"] = banner.decode('utf-8', errors='ignore').strip()
                except:
                    pass
        except Exception as e:
            logger.debug(f"Ошибка при сканировании {ip}:{port} - {e}")
            result["error"] = str(e)
        finally:
            sock.close()
        return result
    
    def scan_ip(self, ip: str, ports: Optional[List[int]] = None) -> Dict[str, Any]:
        if ports is None:
            ports = self.common_ports
        scan_results = {"ip": ip, "timestamp": time.time(), "ports": []}
        threads = []
        results = [None] * len(ports)
        def scan_worker(ip, port, index):
            results[index] = self.scan_port(ip, port)
        for i, port in enumerate(ports):
            thread = threading.Thread(target=scan_worker, args=(ip, port, i))
            thread.daemon = True
            threads.append(thread)
            thread.start()
            if len(threads) >= self.threads:
                for t in threads:
                    t.join()
                threads = []
        for thread in threads:
            thread.join()
        scan_results["ports"] = [r for r in results if r["state"] == "open"]
        return scan_results
    
    def check_changes(self, ip: str, current_scan: Dict[str, Any]) -> Tuple[bool, List[Dict[str, Any]]]:
        changes = []
        previous_scan = self.database.get_last_port_scan(ip)
        if not previous_scan:
            for port_data in current_scan["ports"]:
                changes.append({
                    "type": "new",
                    "port": port_data["port"],
                    "service": port_data["service"],
                    "message": f"Обнаружен новый открытый порт: {port_data['port']} ({port_data['service']})"
                })
            return bool(changes), changes
        prev_ports = {p["port"]: p for p in previous_scan["ports"]}
        curr_ports = {p["port"]: p for p in current_scan["ports"]}
        for port, data in curr_ports.items():
            if port not in prev_ports:
                changes.append({
                    "type": "new",
                    "port": port,
                    "service": data["service"],
                    "message": f"Обнаружен новый открытый порт: {port} ({data['service']})"
                })
        for port, data in prev_ports.items():
            if port not in curr_ports:
                changes.append({
                    "type": "closed",
                    "port": port,
                    "service": data["service"],
                    "message": f"Закрыт ранее открытый порт: {port} ({data['service']})"
                })
        for port, curr_data in curr_ports.items():
            if port in prev_ports:
                prev_data = prev_ports[port]
                if curr_data["service"] != prev_data["service"]:
                    changes.append({
                        "type": "service_changed",
                        "port": port,
                        "old_service": prev_data["service"],
                        "new_service": curr_data["service"],
                        "message": f"Изменился сервис на порту {port}: {prev_data['service']} -> {curr_data['service']}"
                    })
                if curr_data["banner"] != prev_data["banner"] and curr_data["banner"] and prev_data["banner"]:
                    changes.append({
                        "type": "banner_changed",
                        "port": port,
                        "message": f"Изменился баннер на порту {port}"
                    })
        return bool(changes), changes
    
    def scan(self, ip_list: List[str]) -> List[Dict[str, Any]]:  # Переименован из run_scan
        reports = []
        for ip in ip_list:
            logger.info(f"Сканирование портов для {ip}")
            try:
                scan_result = self.scan_ip(ip)
                has_changes, changes = self.check_changes(ip, scan_result)
                self.database.save_port_scan(scan_result)
                if has_changes:
                    report = {
                        "ip": ip,
                        "timestamp": scan_result["timestamp"],
                        "changes": changes
                    }
                    reports.append(report)
                    logger.info(f"Обнаружены изменения в портах для {ip}: {len(changes)} изменений")
                else:
                    logger.info(f"Изменений в портах для {ip} не обнаружено")
            except Exception as e:
                logger.error(f"Ошибка при сканировании портов для {ip}: {e}")
        return reports

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Использование: python port_scanner.py <ip>")
        sys.exit(1)
    class MockConfig:
        def get(self, section, option, fallback=None):
            if option == 'common_ports':
                return '21,22,23,25,80,443,3306,8080'
            return fallback
        def getint(self, section, option, fallback=None):
            return fallback
    class MockDatabase:
        def get_last_port_scan(self, ip):
            return None
        def save_port_scan(self, scan_result):
            print(f"Сохранено в БД: {json.dumps(scan_result, indent=2)}")
    scanner = PortScanner(MockDatabase(), MockConfig())
    result = scanner.scan([sys.argv[1]])
    print(f"Результаты сканирования для {sys.argv[1]}:")
    print(json.dumps(result, indent=2))