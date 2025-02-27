import logging
import sqlite3
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

import config

logger = logging.getLogger(__name__)

# Константы для имен таблиц
IP_STATES_TABLE = 'ip_states'
IP_CHANGES_TABLE = 'ip_changes'
WEBSITE_STATES_TABLE = 'website_states'
WEBSITE_CHANGES_TABLE = 'website_changes'
CERT_INFO_TABLE = 'cert_info'
PORT_STATES_TABLE = 'port_states'
DNS_RECORDS_TABLE = 'dns_records'
DNS_CHANGES_TABLE = 'dns_changes'
SECURITY_HEADERS_TABLE = 'security_headers'


class Database:
    def __init__(self):
        self.db_name = config.DB_NAME
        self.connection = None

    def initialize(self) -> None:
        try:
            self.connection = sqlite3.connect(self.db_name, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row
            self._create_tables()
            self._migrate_database()
            logger.info(f"База данных {self.db_name} инициализирована")
        except Exception as e:
            logger.error(f"Ошибка при инициализации базы данных: {str(e)}")
            raise  # Перебрасываем исключение, чтобы остановить приложение

    def _create_tables(self) -> None:
        cursor = self.connection.cursor()
        try:
            cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS {IP_STATES_TABLE} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                is_up INTEGER,
                hostname TEXT,
                scan_time TEXT,
                description TEXT,
                data TEXT
            )
            ''')
            cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS {IP_CHANGES_TABLE} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                old_state TEXT,
                new_state TEXT,
                change_time TEXT
            )
            ''')
            cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS {WEBSITE_STATES_TABLE} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                is_up INTEGER,
                status_code INTEGER,
                response_time INTEGER,
                error TEXT,
                check_time TEXT,
                data TEXT
            )
            ''')
            cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS {WEBSITE_CHANGES_TABLE} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                old_state TEXT,
                new_state TEXT,
                change_time TEXT
            )
            ''')
            cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS {CERT_INFO_TABLE} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
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
            cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS {PORT_STATES_TABLE} (
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
            cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS {DNS_RECORDS_TABLE} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                record_type TEXT,
                value TEXT,
                ttl INTEGER,
                check_time TEXT,
                UNIQUE(domain, record_type, value)
            )
            ''')
            cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS {DNS_CHANGES_TABLE} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                record_type TEXT,
                old_values TEXT,
                new_values TEXT,
                change_time TEXT
            )
            ''')
            cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS {SECURITY_HEADERS_TABLE} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                header_name TEXT,
                header_value TEXT,
                check_time TEXT,
                UNIQUE(url, header_name)
            )
            ''')
            self.connection.commit()
        finally:
            cursor.close()


    def _migrate_database(self) -> None:
        cursor = self.connection.cursor()
        try:
            cursor.execute("SELECT description FROM ip_states")
            # Если запрос выполнился, столбец уже существует
            logger.info("Столбец description уже существует в ip_states")
        except sqlite3.OperationalError:
            # Если столбца нет, добавляем
            cursor.execute(f"ALTER TABLE {IP_STATES_TABLE} ADD COLUMN description TEXT")
            logger.info("Миграция: добавлен столбец description в ip_states")
        except Exception as e:  # Обрабатываем другие возможные ошибки
            logger.error(f"Ошибка миграции: {str(e)}")
        finally:
            cursor.close()

        self.connection.commit()


    def save_ip_state(self, state: Dict[str, Any]) -> None:
        cursor = self.connection.cursor()
        try:
            state_copy = state.copy()
            if "scan_time" in state_copy and isinstance(state_copy["scan_time"], datetime):
                state_copy["scan_time"] = state_copy["scan_time"].isoformat()

            # Используем parameterized query для большей безопасности
            cursor.execute(f'''
                INSERT OR REPLACE INTO {IP_STATES_TABLE}
                (ip_address, is_up, hostname, scan_time, description, data)
                VALUES (:ip_address, :is_up, :hostname, :scan_time, :description, :data)
            ''', {
                'ip_address': state_copy["ip_address"],
                'is_up': 1 if state_copy.get("is_up", False) else 0,
                'hostname': state_copy.get("hostname", ""),
                'scan_time': state_copy.get("scan_time", datetime.now().isoformat()),
                'description': state_copy.get("description", ""),
                'data': json.dumps(state_copy)
            })
            self.connection.commit()
        except Exception as e:
            logger.error(f"Ошибка при сохранении состояния IP {state.get('ip_address', 'unknown')}: {str(e)}")
            self.connection.rollback()
        finally:
            cursor.close()



    def get_ip_state(self, ip_address: str) -> Optional[Dict[str, Any]]:
        cursor = self.connection.cursor()
        try:
            cursor.execute(f'SELECT * FROM {IP_STATES_TABLE} WHERE ip_address = ?', (ip_address,))
            row = cursor.fetchone()
            if row:
                data = dict(row)
                if "scan_time" in data and data["scan_time"]:
                    data["scan_time"] = datetime.fromisoformat(data["scan_time"])
                return data
            return None
        except Exception as e:
            logger.error(f"Ошибка при получении состояния IP {ip_address}: {str(e)}")
            return None
        finally:
            cursor.close()


    def delete_ip_state(self, ip_address: str) -> bool:
        cursor = self.connection.cursor()
        try:
            cursor.execute(f'DELETE FROM {IP_STATES_TABLE} WHERE ip_address = ?', (ip_address,))
            self.connection.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Ошибка при удалении IP {ip_address}: {str(e)}")
            self.connection.rollback()
            return False
        finally:
            cursor.close()


    def save_ip_change(self, change: Dict[str, Any]) -> None:
        cursor = self.connection.cursor()
        try:
            # Преобразуем datetime в строку перед сериализацией
            change_copy = change.copy()
            if "change_time" in change_copy and isinstance(change_copy["change_time"], datetime):
                change_copy["change_time"] = change_copy["change_time"].isoformat()
            cursor.execute(f'''
            INSERT INTO {IP_CHANGES_TABLE}
            (ip_address, old_state, new_state, change_time)
            VALUES (?, ?, ?, ?)
            ''', (
                change_copy["ip_address"],
                json.dumps(change_copy["old_state"]),
                json.dumps(change_copy["new_state"]),
                change_copy["change_time"]
            ))
            self.connection.commit()
        except Exception as e:
            logger.error(f"Ошибка при сохранении изменения IP {change.get('ip_address', 'unknown')}: {str(e)}")
            self.connection.rollback()
        finally:
            cursor.close()



    def save_website_state(self, state: Dict[str, Any]) -> None:
        cursor = self.connection.cursor()
        try:
            state_copy = state.copy()
            if "check_time" in state_copy and isinstance(state_copy["check_time"], datetime):
                state_copy["check_time"] = state_copy["check_time"].isoformat()

            cursor.execute(f'''
                INSERT OR REPLACE INTO {WEBSITE_STATES_TABLE}
                (url, is_up, status_code, response_time, error, check_time, data)
                VALUES (:url, :is_up, :status_code, :response_time, :error, :check_time, :data)
            ''', {
                'url': state_copy["url"],
                'is_up': 1 if state_copy.get("is_up", False) else 0,
                'status_code': state_copy.get("status_code"),
                'response_time': state_copy.get("response_time"),
                'error': state_copy.get("error"),
                'check_time': state_copy.get("check_time", datetime.now().isoformat()),
                'data': json.dumps(state_copy)
            })
            self.connection.commit()
        except Exception as e:
            logger.error(f"Ошибка при сохранении состояния сайта {state.get('url', 'unknown')}: {str(e)}")
            self.connection.rollback()
        finally:
            cursor.close()



    def get_website_state(self, url: str) -> Optional[Dict[str, Any]]:
        cursor = self.connection.cursor()
        try:
            cursor.execute(f'SELECT * FROM {WEBSITE_STATES_TABLE} WHERE url = ?', (url,))
            row = cursor.fetchone()
            if row:
                data = dict(row)
                if "check_time" in data and data["check_time"]:
                    data["check_time"] = datetime.fromisoformat(data["check_time"])
                return data
            return None
        except Exception as e:
            logger.error(f"Ошибка при получении состояния сайта {url}: {str(e)}")
            return None
        finally:
            cursor.close()


    def get_website_state_by_id(self, website_id: int) -> Optional[Dict[str, Any]]:
        cursor = self.connection.cursor()
        try:
            cursor.execute(f'SELECT * FROM {WEBSITE_STATES_TABLE} WHERE id = ?', (website_id,))
            row = cursor.fetchone()
            if row:
                data = dict(row)
                if "check_time" in data and data["check_time"]:
                    data["check_time"] = datetime.fromisoformat(data["check_time"])
                return data
            return None
        except Exception as e:
            logger.error(f"Ошибка при получении состояния сайта по ID {website_id}: {str(e)}")
            return None
        finally:
            cursor.close()

    def update_website_state_by_id(self, website_id: int, new_state: Dict[str, Any]):
        cursor = self.connection.cursor()
        try:
            if "check_time" in new_state and isinstance(new_state["check_time"], datetime):
                new_state["check_time"] = new_state["check_time"].isoformat()

            cursor.execute(f'''
                UPDATE {WEBSITE_STATES_TABLE}
                SET url = :url, is_up = :is_up, status_code = :status_code,
                response_time = :response_time, error = :error, check_time = :check_time,
                data = :data
                WHERE id = :website_id
            ''',{
                'url': new_state["url"],
                'is_up': 1 if new_state.get("is_up", False) else 0,
                'status_code': new_state.get("status_code"),
                'response_time': new_state.get("response_time"),
                'error': new_state.get("error"),
                'check_time': new_state.get("check_time", datetime.now().isoformat()),
                'data': json.dumps(new_state),
                'website_id': website_id
            })
            self.connection.commit()

        except Exception as e:
            logger.error(f"Ошибка при обновлении состояния сайта по ID {website_id}: {str(e)}")
            self.connection.rollback()
        finally:
            cursor.close()

    def delete_website_state(self, url: str) -> bool:
        cursor = self.connection.cursor()
        try:
            cursor.execute(f'DELETE FROM {WEBSITE_STATES_TABLE} WHERE url = ?', (url,))
            self.connection.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Ошибка при удалении сайта {url}: {str(e)}")
            self.connection.rollback()
            return False
        finally:
            cursor.close()


    def save_website_change(self, change: Dict[str, Any]) -> None:
        cursor = self.connection.cursor()
        try:
            change_copy = change.copy()
            if "change_time" in change_copy and isinstance(change_copy["change_time"], datetime):
                change_copy["change_time"] = change_copy["change_time"].isoformat()
            cursor.execute(f'''
            INSERT INTO {WEBSITE_CHANGES_TABLE}
            (url, old_state, new_state, change_time)
            VALUES (?, ?, ?, ?)
            ''', (
                change_copy["url"],
                json.dumps(change_copy["old_state"]),
                json.dumps(change_copy["new_state"]),
                change_copy["change_time"]
            ))
            self.connection.commit()
        except Exception as e:
            logger.error(f"Ошибка при сохранении изменения сайта {change.get('url', 'unknown')}: {str(e)}")
            self.connection.rollback()
        finally:
            cursor.close()


    def save_cert_info(self, cert_info: Dict[str, Any]) -> None:
        cursor = self.connection.cursor()
        try:
            cert_copy = cert_info.copy()
            for key in ["not_before", "not_after", "check_time"]:
                if key in cert_copy and isinstance(cert_copy[key], datetime):
                    cert_copy[key] = cert_copy[key].isoformat()
            cursor.execute(f'''
            INSERT OR REPLACE INTO {CERT_INFO_TABLE}
            (domain, common_name, issuer, organization, not_before, not_after,
             days_to_expiry, is_expiring, is_expired, check_time, data)
            VALUES (:domain, :common_name, :issuer, :organization, :not_before, :not_after,
             :days_to_expiry, :is_expiring, :is_expired, :check_time, :data)
            ''', {
                'domain': cert_copy["domain"],
                'common_name': cert_copy.get("common_name", "N/A"),
                'issuer': cert_copy.get("issuer", "N/A"),
                'organization': cert_copy.get("organization", "N/A"),
                'not_before': cert_copy.get("not_before", ""),
                'not_after': cert_copy.get("not_after", ""),
                'days_to_expiry': cert_copy.get("days_to_expiry", 0),
                'is_expiring': 1 if cert_copy.get("is_expiring", False) else 0,
                'is_expired': 1 if cert_copy.get("is_expired", False) else 0,
                'check_time': cert_copy.get("check_time", datetime.now().isoformat()),
                'data': json.dumps(cert_copy)
            })
            self.connection.commit()
        except Exception as e:
            logger.error(f"Ошибка при сохранении информации о сертификате {cert_info.get('domain', 'unknown')}: {str(e)}")
            self.connection.rollback()
        finally:
            cursor.close()



    def get_cert_info(self, domain: str) -> Optional[Dict[str, Any]]:
        cursor = self.connection.cursor()
        try:
            cursor.execute(f'SELECT * FROM {CERT_INFO_TABLE} WHERE domain = ?', (domain,))
            row = cursor.fetchone()
            if row:
                data = dict(row)
                for key in ["not_before", "not_after", "check_time"]:
                    if key in data and data[key]:
                        data[key] = datetime.fromisoformat(data[key])
                return data
            return None
        except Exception as e:
            logger.error(f"Ошибка при получении информации о сертификате {domain}: {str(e)}")
            return None
        finally:
            cursor.close()

    def get_cert_info_by_id(self, cert_id: int) -> Optional[Dict[str, Any]]:
        cursor = self.connection.cursor()
        try:
            cursor.execute(f'SELECT * FROM {CERT_INFO_TABLE} WHERE id = ?', (cert_id,))
            row = cursor.fetchone()
            if row:
                data = dict(row)
                for key in ["not_before", "not_after", "check_time"]:
                    if key in data and data[key]:
                        data[key] = datetime.fromisoformat(data[key])
                return data
            return None
        except Exception as e:
            logger.error(f"Ошибка при получении информации о сертификате по id {cert_id}: {str(e)}")
            return None
        finally:
            cursor.close()

    def update_cert_info_by_id(self, cert_id: int, new_state: Dict[str, Any]):
        cursor = self.connection.cursor()
        try:
            cert_copy = new_state.copy()
            for key in ["not_before", "not_after", "check_time"]:
                if key in cert_copy and isinstance(cert_copy[key], datetime):
                    cert_copy[key] = cert_copy[key].isoformat()

            cursor.execute(f'''
            UPDATE {CERT_INFO_TABLE}
            SET  domain = :domain, common_name = :common_name, issuer = :issuer, organization = :organization,
            not_before = :not_before, not_after = :not_after,
            days_to_expiry = :days_to_expiry, is_expiring = :is_expiring, is_expired = :is_expired, check_time = :check_time, data = :data
            WHERE id = :cert_id
            ''', {
                'domain': cert_copy["domain"],
                'common_name': cert_copy.get("common_name", "N/A"),
                'issuer': cert_copy.get("issuer", "N/A"),
                'organization': cert_copy.get("organization", "N/A"),
                'not_before': cert_copy.get("not_before", ""),
                'not_after': cert_copy.get("not_after", ""),
                'days_to_expiry': cert_copy.get("days_to_expiry", 0),
                'is_expiring': 1 if cert_copy.get("is_expiring", False) else 0,
                'is_expired': 1 if cert_copy.get("is_expired", False) else 0,
                'check_time': cert_copy.get("check_time", datetime.now().isoformat()),
                'data': json.dumps(cert_copy),
                'cert_id': cert_id  #  Используем cert_id
            })
            self.connection.commit()
        except Exception as e:
            logger.error(f"Ошибка при обновлении сертификата с id {cert_id}: {str(e)}")
            self.connection.rollback()
        finally:
            cursor.close()


    def delete_cert_info(self, domain: str) -> bool:
        cursor = self.connection.cursor()
        try:
            cursor.execute(f'DELETE FROM {CERT_INFO_TABLE} WHERE domain = ?', (domain,))
            self.connection.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Ошибка при удалении сертификата {domain}: {str(e)}")
            self.connection.rollback()
            return False
        finally:
            cursor.close()


# core/database.py
    def get_all_records(self, table_name: str, limit: int = None, offset: int = 0) -> List[Dict[str, Any]]:
        cursor = self.connection.cursor()
        try:
            valid_tables = {
                'ip_scan_results': IP_STATES_TABLE,
                'website_monitoring': WEBSITE_STATES_TABLE,
                'ssl_certificates': CERT_INFO_TABLE,
                'port_scanning': PORT_STATES_TABLE,
                'dns_monitoring': DNS_RECORDS_TABLE,
                'security_headers': SECURITY_HEADERS_TABLE
            }
            if table_name not in valid_tables:
                raise ValueError(f"Недопустимое имя таблицы: {table_name}")
            actual_table = valid_tables[table_name]

            query = f'SELECT * FROM {actual_table}'
            params = []
            if limit is not None:
                query += ' LIMIT ? OFFSET ?'
                params = [limit, offset]

            cursor.execute(query, params)
            rows = cursor.fetchall()
            result = []
            for row in rows:
                data = dict(row)
                for key in ['scan_time', 'check_time', 'change_time', 'not_before', 'not_after']:
                    if key in data and data[key]:
                        try:
                            data[key] = datetime.fromisoformat(data[key])
                        except (ValueError, TypeError):
                            pass
                result.append(data)
            return result
        except Exception as e:
            logger.error(f"Ошибка при получении записей из таблицы {table_name}: {str(e)}")
            return []
        finally:
            cursor.close()


    def save_port_scan(self, scan_result: Dict[str, Any]) -> None:
        cursor = self.connection.cursor()
        try:
            for port_data in scan_result.get("ports", []):
                cursor.execute(f'''
                INSERT OR REPLACE INTO {PORT_STATES_TABLE}
                (ip_address, port, protocol, service, is_open, scan_time)
                VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    scan_result["ip"],
                    port_data.get("port"),
                    port_data.get("protocol", "tcp"),
                    port_data.get("service", "unknown"),
                    1 if port_data.get("state") == "open" else 0,
                    datetime.fromtimestamp(scan_result["timestamp"]).isoformat()
                ))
            self.connection.commit()
        except Exception as e:
            logger.error(f"Ошибка при сохранении результатов сканирования портов для {scan_result.get('ip', 'unknown')}: {str(e)}")
            self.connection.rollback()
        finally:
            cursor.close()


    def get_last_port_scan(self, ip: str) -> Optional[Dict[str, Any]]:
        cursor = self.connection.cursor()
        try:
            cursor.execute(f'''
            SELECT port, service, is_open, scan_time
            FROM {PORT_STATES_TABLE}
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
        finally:
            cursor.close()


    def delete_port_state(self, ip_address: str) -> bool:
        cursor = self.connection.cursor()
        try:
            cursor.execute(f'DELETE FROM {PORT_STATES_TABLE} WHERE ip_address = ?', (ip_address,))
            self.connection.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Ошибка при удалении портов для {ip_address}: {str(e)}")
            self.connection.rollback()
            return False
        finally:
            cursor.close()


    def save_dns_scan(self, dns_data: Dict[str, Any]) -> None:
        cursor = self.connection.cursor()
        try:
            for record_type, records in dns_data.get("records", {}).items():
                for value in records:
                    value_str = str(value) if not isinstance(value, dict) else json.dumps(value)
                    cursor.execute(f'''
                    INSERT OR REPLACE INTO {DNS_RECORDS_TABLE}
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
            logger.error(f"Ошибка при сохранении DNS-данных для {dns_data.get('domain', 'unknown')}: {str(e)}")
            self.connection.rollback()
        finally:
            cursor.close()


    def get_last_dns_scan(self, domain: str) -> Optional[Dict[str, Any]]:
        cursor = self.connection.cursor()
        try:
            cursor.execute(f'''
            SELECT record_type, value, ttl, check_time
            FROM {DNS_RECORDS_TABLE}
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
        finally:
            cursor.close()


    def delete_dns_records(self, domain: str) -> bool:
        cursor = self.connection.cursor()
        try:
            cursor.execute(f'DELETE FROM {DNS_RECORDS_TABLE} WHERE domain = ?', (domain,))
            self.connection.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Ошибка при удалении DNS-записей для {domain}: {str(e)}")
            self.connection.rollback()
            return False
        finally:
            cursor.close()


    def save_security_headers_check(self, check_data: Dict[str, Any]) -> None:
        cursor = self.connection.cursor()
        try:
            for header_name, header_value in check_data.get("headers", {}).items():
                cursor.execute(f'''
                INSERT OR REPLACE INTO {SECURITY_HEADERS_TABLE}
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
            logger.error(f"Ошибка при сохранении заголовков для {check_data.get('url', 'unknown')}: {str(e)}")
            self.connection.rollback()
        finally:
            cursor.close()


    def get_last_security_headers_check(self, url: str) -> Optional[Dict[str, Any]]:
        cursor = self.connection.cursor()
        try:
            cursor.execute(f'''
            SELECT header_name, header_value, check_time
            FROM {SECURITY_HEADERS_TABLE}
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
                    "security_score": 0  #  Добавить расчет оценки, если нужно
                }
            return None
        except Exception as e:
            logger.error(f"Ошибка при получении последних заголовков для {url}: {str(e)}")
            return None
        finally:
            cursor.close()


    def delete_security_headers(self, url: str) -> bool:
        cursor = self.connection.cursor()
        try:
            cursor.execute(f'DELETE FROM {SECURITY_HEADERS_TABLE} WHERE url = ?', (url,))
            self.connection.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Ошибка при удалении заголовков для {url}: {str(e)}")
            self.connection.rollback()
            return False
        finally:
            cursor.close()


    def close(self) -> None:
        if self.connection:
            self.connection.close()
            logger.info("Соединение с базой данных закрыто")