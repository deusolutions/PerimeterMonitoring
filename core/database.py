"""
Модуль для работы с базой данных
"""
import logging
import sqlite3
import json
from datetime import datetime
from typing import Dict, Any, List, Optional, Union

import config

logger = logging.getLogger(__name__)

class Database:
    """Класс для работы с базой данных"""
    
    def __init__(self):
        self.db_name = config.DB_NAME
        self.connection = None
        
    def initialize(self) -> None:
        try:
            self.connection = sqlite3.connect(self.db_name, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row
            self._create_tables()
            logger.info(f"База данных {self.db_name} инициализирована")
        except Exception as e:
            logger.error(f"Ошибка при инициализации базы данных: {str(e)}")
            raise
    
    def _create_tables(self) -> None:
        cursor = self.connection.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_states (
            ip_address TEXT PRIMARY KEY,
            is_up INTEGER,
            hostname TEXT,
            scan_time TEXT,
            data TEXT
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            old_state TEXT,
            new_state TEXT,
            change_time TEXT
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS website_states (
            url TEXT PRIMARY KEY,
            is_up INTEGER,
            status_code INTEGER,
            response_time INTEGER,
            error TEXT,
            check_time TEXT,
            data TEXT
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS website_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            old_state TEXT,
            new_state TEXT,
            change_time TEXT
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS cert_info (
            domain TEXT PRIMARY KEY,
            common_name TEXT,
            issuer TEXT,
            organization TEXT,
            not_before TEXT,
            not_after TEXT,
            days_to_expiry INTEGER,
            is_expiring INTEGER,
            is_expired INTEGER,
            check_time TEXT,
            data TEXT
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS port_states (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            port INTEGER,
            protocol TEXT,
            service TEXT,
            is_open INTEGER,
            scan_time TEXT,
            UNIQUE(ip_address, port, protocol)
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS dns_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            record_type TEXT,
            value TEXT,
            ttl INTEGER,
            check_time TEXT,
            UNIQUE(domain, record_type, value)
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS dns_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            record_type TEXT,
            old_values TEXT,
            new_values TEXT,
            change_time TEXT
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_headers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            header_name TEXT,
            header_value TEXT,
            check_time TEXT,
            UNIQUE(url, header_name)
        )
        ''')
        self.connection.commit()
    
    def save_ip_state(self, state: Dict[str, Any]) -> None:
        cursor = self.connection.cursor()
        try:
            cursor.execute('''
            INSERT OR REPLACE INTO ip_states 
            (ip_address, is_up, hostname, scan_time, data) 
            VALUES (?, ?, ?, ?, ?)
            ''', (
                state["ip_address"],
                1 if state["is_up"] else 0,
                state["hostname"],
                state["scan_time"].isoformat(),
                json.dumps(state)
            ))
            self.connection.commit()
        except Exception as e:
            logger.error(f"Ошибка при сохранении состояния IP {state['ip_address']}: {str(e)}")
            self.connection.rollback()
    
    def get_ip_state(self, ip_address: str) -> Optional[Dict[str, Any]]:
        cursor = self.connection.cursor()
        try:
            cursor.execute('SELECT data FROM ip_states WHERE ip_address = ?', (ip_address,))
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
            return None
        except Exception as e:
            logger.error(f"Ошибка при получении состояния IP {ip_address}: {str(e)}")
            return None
    
    def save_ip_change(self, change: Dict[str, Any]) -> None:
        cursor = self.connection.cursor()
        try:
            cursor.execute('''
            INSERT INTO ip_changes 
            (ip_address, old_state, new_state, change_time) 
            VALUES (?, ?, ?, ?)
            ''', (
                change["ip_address"],
                json.dumps(change["old_state"]),
                json.dumps(change["new_state"]),
                change["change_time"].isoformat()
            ))
            self.connection.commit()
        except Exception as e:
            logger.error(f"Ошибка при сохранении изменения IP {change['ip_address']}: {str(e)}")
            self.connection.rollback()
    
    def save_website_state(self, state: Dict[str, Any]) -> None:
        cursor = self.connection.cursor()
        try:
            cursor.execute('''
            INSERT OR REPLACE INTO website_states 
            (url, is_up, status_code, response_time, error, check_time, data) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                state["url"],
                1 if state["is_up"] else 0,
                state["status_code"],
                state["response_time"],
                state["error"],
                state["check_time"].isoformat(),
                json.dumps(state)
            ))
            self.connection.commit()
        except Exception as e:
            logger.error(f"Ошибка при сохранении состояния сайта {state['url']}: {str(e)}")
            self.connection.rollback()
    
    def get_website_state(self, url: str) -> Optional[Dict[str, Any]]:
        cursor = self.connection.cursor()
        try:
            cursor.execute('SELECT data FROM website_states WHERE url = ?', (url,))
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
            return None
        except Exception as e:
            logger.error(f"Ошибка при получении состояния сайта {url}: {str(e)}")
            return None
    
    def save_website_change(self, change: Dict[str, Any]) -> None:
        cursor = self.connection.cursor()
        try:
            cursor.execute('''
            INSERT INTO website_changes 
            (url, old_state, new_state, change_time) 
            VALUES (?, ?, ?, ?)
            ''', (
                change["url"],
                json.dumps(change["old_state"]),
                json.dumps(change["new_state"]),
                change["change_time"].isoformat()
            ))
            self.connection.commit()
        except Exception as e:
            logger.error(f"Ошибка при сохранении изменения сайта {change['url']}: {str(e)}")
            self.connection.rollback()
    
    def save_cert_info(self, cert_info: Dict[str, Any]) -> None:
        cursor = self.connection.cursor()
        try:
            not_before = cert_info["not_before"].isoformat() if "not_before" in cert_info else None
            not_after = cert_info["not_after"].isoformat() if "not_after" in cert_info else None
            cursor.execute('''
            INSERT OR REPLACE INTO cert_info 
            (domain, common_name, issuer, organization, not_before, not_after, 
             days_to_expiry, is_expiring, is_expired, check_time, data) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cert_info["domain"],
                cert_info.get("common_name", "N/A"),
                cert_info.get("issuer", "N/A"),
                cert_info.get("organization", "N/A"),
                not_before,
                not_after,
                cert_info.get("days_to_expiry"),
                1 if cert_info.get("is_expiring", False) else 0,
                1 if cert_info.get("is_expired", False) else 0,
                cert_info["check_time"].isoformat(),
                json.dumps(cert_info)
            ))
            self.connection.commit()
        except Exception as e:
            logger.error(f"Ошибка при сохранении информации о сертификате {cert_info['domain']}: {str(e)}")
            self.connection.rollback()
    
    def get_cert_info(self, domain: str) -> Optional[Dict[str, Any]]:
        cursor = self.connection.cursor()
        try:
            cursor.execute('SELECT data FROM cert_info WHERE domain = ?', (domain,))
            row = cursor.fetchone()
            if row:
                cert_info = json.loads(row[0])
                if "not_before" in cert_info and cert_info["not_before"]:
                    cert_info["not_before"] = datetime.fromisoformat(cert_info["not_before"])
                if "not_after" in cert_info and cert_info["not_after"]:
                    cert_info["not_after"] = datetime.fromisoformat(cert_info["not_after"])
                if "check_time" in cert_info and cert_info["check_time"]:
                    cert_info["check_time"] = datetime.fromisoformat(cert_info["check_time"])
                return cert_info
            return None
        except Exception as e:
            logger.error(f"Ошибка при получении информации о сертификате {domain}: {str(e)}")
            return None
    
    def get_all_records(self, table_name: str, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        cursor = self.connection.cursor()
        try:
            valid_tables = {
                'ip_scan_results': 'ip_states',
                'website_monitoring': 'website_states',
                'ssl_certificates': 'cert_info',
                'port_scanning': 'port_states',
                'dns_monitoring': 'dns_records',
                'security_headers': 'security_headers'
            }
            if table_name not in valid_tables:
                raise ValueError(f"Недопустимое имя таблицы: {table_name}")
            actual_table = valid_tables[table_name]
            cursor.execute(f'''
                SELECT * FROM {actual_table}
                LIMIT ? OFFSET ?
            ''', (limit, offset))
            rows = cursor.fetchall()
            result = []
            for row in rows:
                row_dict = dict(row)
                if 'data' in row_dict and row_dict['data']:
                    data = json.loads(row_dict['data'])
                    for key in ['scan_time', 'check_time', 'change_time', 'not_before', 'not_after']:
                        if key in data and data[key]:
                            data[key] = datetime.fromisoformat(data[key])
                    result.append(data)
                else:
                    result.append(row_dict)
            return result
        except Exception as e:
            logger.error(f"Ошибка при получении записей из таблицы {table_name}: {str(e)}")
            raise
    
    # Новые методы для модулей
    def save_port_scan(self, scan_result: Dict[str, Any]) -> None:
        cursor = self.connection.cursor()
        try:
            for port_data in scan_result["ports"]:
                cursor.execute('''
                INSERT OR REPLACE INTO port_states 
                (ip_address, port, protocol, service, is_open, scan_time) 
                VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    scan_result["ip"],
                    port_data["port"],
                    "tcp",  # Предполагаем TCP, можно добавить поддержку других протоколов
                    port_data["service"],
                    1,
                    datetime.fromtimestamp(scan_result["timestamp"]).isoformat()
                ))
            self.connection.commit()
        except Exception as e:
            logger.error(f"Ошибка при сохранении результатов сканирования портов для {scan_result['ip']}: {str(e)}")
            self.connection.rollback()
    
    def get_last_port_scan(self, ip: str) -> Optional[Dict[str, Any]]:
        cursor = self.connection.cursor()
        try:
            cursor.execute('''
            SELECT port, service, is_open, scan_time 
            FROM port_states 
            WHERE ip_address = ? AND is_open = 1
            ORDER BY scan_time DESC
            ''', (ip,))
            rows = cursor.fetchall()
            if rows:
                ports = [{"port": row["port"], "service": row["service"]} for row in rows]
                return {"ip": ip, "ports": ports, "timestamp": datetime.fromisoformat(rows[0]["scan_time"]).timestamp()}
            return None
        except Exception as e:
            logger.error(f"Ошибка при получении последнего сканирования портов для {ip}: {str(e)}")
            return None
    
    def save_dns_scan(self, dns_data: Dict[str, Any]) -> None:
        cursor = self.connection.cursor()
        try:
            for record_type, records in dns_data["records"].items():
                for value in records:
                    value_str = str(value) if not isinstance(value, dict) else json.dumps(value)
                    cursor.execute('''
                    INSERT OR REPLACE INTO dns_records 
                    (domain, record_type, value, ttl, check_time) 
                    VALUES (?, ?, ?, ?, ?)
                    ''', (
                        dns_data["domain"],
                        record_type,
                        value_str,
                        dns_data.get("ttl", 0),
                        datetime.fromtimestamp(dns_data["timestamp"]).isoformat()
                    ))
            self.connection.commit()
        except Exception as e:
            logger.error(f"Ошибка при сохранении DNS-данных для {dns_data['domain']}: {str(e)}")
            self.connection.rollback()
    
    def get_last_dns_scan(self, domain: str) -> Optional[Dict[str, Any]]:
        cursor = self.connection.cursor()
        try:
            cursor.execute('''
            SELECT record_type, value, ttl, check_time 
            FROM dns_records 
            WHERE domain = ?
            ORDER BY check_time DESC
            ''', (domain,))
            rows = cursor.fetchall()
            if rows:
                records = {}
                for row in rows:
                    record_type = row["record_type"]
                    value = json.loads(row["value"]) if row["value"].startswith("{") else row["value"]
                    if record_type not in records:
                        records[record_type] = []
                    records[record_type].append(value)
                return {
                    "domain": domain,
                    "records": records,
                    "ttl": rows[0]["ttl"],
                    "timestamp": datetime.fromisoformat(rows[0]["check_time"]).timestamp()
                }
            return None
        except Exception as e:
            logger.error(f"Ошибка при получении последнего DNS-сканирования для {domain}: {str(e)}")
            return None
    
    def save_security_headers_check(self, check_data: Dict[str, Any]) -> None:
        cursor = self.connection.cursor()
        try:
            for header_name, header_value in check_data["headers"].items():
                cursor.execute('''
                INSERT OR REPLACE INTO security_headers 
                (url, header_name, header_value, check_time) 
                VALUES (?, ?, ?, ?)
                ''', (
                    check_data["url"],
                    header_name,
                    header_value,
                    datetime.fromtimestamp(check_data["timestamp"]).isoformat()
                ))
            self.connection.commit()
        except Exception as e:
            logger.error(f"Ошибка при сохранении заголовков для {check_data['url']}: {str(e)}")
            self.connection.rollback()
    
def get_last_security_headers_check(self, url: str) -> Optional[Dict[str, Any]]:
    cursor = self.connection.cursor()
    try:
        cursor.execute('''
        SELECT header_name, header_value, check_time 
        FROM security_headers 
        WHERE url = ?
        ORDER BY check_time DESC
        ''', (url,))
        rows = cursor.fetchall()
        if rows:
            headers = {row["header_name"]: row["header_value"] for row in rows}
            return {
                "url": url,
                "headers": headers,
                "timestamp": datetime.fromisoformat(rows[0]["check_time"]).timestamp(),
                "security_score": 0  # Значение по умолчанию, так как оно не хранится в таблице
            }
        return None
    except Exception as e:
        logger.error(f"Ошибка при получении последних заголовков для {url}: {str(e)}")
        return None
    
    def close(self) -> None:
        if self.connection:
            self.connection.close()
            logger.info("Соединение с базой данных закрыто")