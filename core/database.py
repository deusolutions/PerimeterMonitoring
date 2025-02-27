# core/database.py
import json
import sqlite3
from datetime import datetime
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

IP_STATES_TABLE = 'ip_states'
WEBSITE_STATES_TABLE = 'website_states'
CERT_INFO_TABLE = 'ssl_certificates'
PORT_STATES_TABLE = 'port_scanning'
DNS_RECORDS_TABLE = 'dns_monitoring'
SECURITY_HEADERS_TABLE = 'security_headers'

class Database:
    def __init__(self):
        self.db_name = 'monitoring.db'
        self.connection = sqlite3.connect(self.db_name, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row

    def initialize(self):
        cursor = self.connection.cursor()
        try:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_states (
                    ip_address TEXT PRIMARY KEY,
                    is_up BOOLEAN,
                    hostname TEXT,
                    response_time REAL,
                    description TEXT,
                    scan_time TEXT
                )
            ''')
            try:
                cursor.execute("ALTER TABLE ip_states ADD COLUMN description TEXT")
                logger.info("Столбец description добавлен в ip_states")
            except sqlite3.OperationalError:
                logger.info("Столбец description уже существует в ip_states")

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS website_states (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT UNIQUE,
                    is_up BOOLEAN,
                    status_code INTEGER,
                    response_time REAL,
                    check_time TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ssl_certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE,
                    common_name TEXT,
                    issuer TEXT,
                    organization TEXT,
                    not_before TEXT,
                    not_after TEXT,
                    days_to_expiry INTEGER,
                    is_expiring BOOLEAN,
                    is_expired BOOLEAN,
                    error TEXT,
                    check_time TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS port_scanning (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    port INTEGER,
                    protocol TEXT,
                    service TEXT,
                    is_open BOOLEAN,
                    scan_time TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS dns_monitoring (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT,
                    record_type TEXT,
                    value TEXT,
                    ttl INTEGER,
                    check_time TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_headers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT,
                    header_name TEXT,
                    header_value TEXT,
                    check_time TEXT
                )
            ''')

            self.connection.commit()
            logger.info(f"База данных {self.db_name} инициализирована")
        except Exception as e:
            logger.error(f"Ошибка при инициализации базы данных: {str(e)}")
        finally:
            cursor.close()

    def _convert_datetime(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Преобразует datetime в строку для JSON."""
        result = data.copy()
        for key in ['scan_time', 'check_time', 'not_before', 'not_after']:
            if key in result and isinstance(result[key], datetime):
                result[key] = result[key].isoformat()
        return result

    def save_ip_state(self, state: Dict[str, Any]) -> None:
        cursor = self.connection.cursor()
        try:
            state = self._convert_datetime(state)
            cursor.execute('''
                INSERT OR REPLACE INTO ip_states (ip_address, is_up, hostname, response_time, description, scan_time)
                VALUES (:ip_address, :is_up, :hostname, :response_time, :description, :scan_time)
            ''', state)
            self.connection.commit()
        except Exception as e:
            logger.error(f"Ошибка при сохранении состояния IP {state.get('ip_address', 'unknown')}: {str(e)}")
        finally:
            cursor.close()

    def get_ip_state(self, ip_address: str) -> Dict[str, Any]:
        cursor = self.connection.cursor()
        try:
            cursor.execute('SELECT * FROM ip_states WHERE ip_address = ?', (ip_address,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return {}
        except Exception as e:
            logger.error(f"Ошибка при получении состояния IP {ip_address}: {str(e)}")
            return {}
        finally:
            cursor.close()

    def save_website_state(self, state: Dict[str, Any]) -> None:
        cursor = self.connection.cursor()
        try:
            state = self._convert_datetime(state)
            cursor.execute('''
                INSERT OR REPLACE INTO website_states (url, is_up, status_code, response_time, check_time)
                VALUES (:url, :is_up, :status_code, :response_time, :check_time)
            ''', state)
            self.connection.commit()
        except Exception as e:
            logger.error(f"Ошибка при сохранении состояния сайта {state.get('url', 'unknown')}: {str(e)}")
        finally:
            cursor.close()

    def get_website_state(self, url: str) -> Dict[str, Any]:
        cursor = self.connection.cursor()
        try:
            cursor.execute('SELECT * FROM website_states WHERE url = ?', (url,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return {}
        except Exception as e:
            logger.error(f"Ошибка при получении состояния сайта {url}: {str(e)}")
            return {}
        finally:
            cursor.close()

    def get_website_state_by_id(self, website_id: int) -> Dict[str, Any]:
        cursor = self.connection.cursor()
        try:
            cursor.execute('SELECT * FROM website_states WHERE id = ?', (website_id,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return {}
        except Exception as e:
            logger.error(f"Ошибка при получении состояния сайта по ID {website_id}: {str(e)}")
            return {}
        finally:
            cursor.close()

    def save_cert_info(self, cert_info: Dict[str, Any]) -> None:
        cursor = self.connection.cursor()
        try:
            cert_info = self._convert_datetime(cert_info)
            cursor.execute('''
                INSERT OR REPLACE INTO ssl_certificates (domain, common_name, issuer, organization, not_before, not_after, days_to_expiry, is_expiring, is_expired, error, check_time)
                VALUES (:domain, :common_name, :issuer, :organization, :not_before, :not_after, :days_to_expiry, :is_expiring, :is_expired, :error, :check_time)
            ''', cert_info)
            self.connection.commit()
        except Exception as e:
            logger.error(f"Ошибка при сохранении информации о сертификате {cert_info.get('domain', 'unknown')}: {str(e)}")
        finally:
            cursor.close()

    def get_cert_info(self, domain: str) -> Dict[str, Any]:
        cursor = self.connection.cursor()
        try:
            cursor.execute('SELECT * FROM ssl_certificates WHERE domain = ?', (domain,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return {}
        except Exception as e:
            logger.error(f"Ошибка при получении информации о сертификате {domain}: {str(e)}")
            return {}
        finally:
            cursor.close()

    def save_port_scan(self, scan_result: Dict[str, Any]) -> None:
        cursor = self.connection.cursor()
        try:
            ip = scan_result['ip']
            timestamp = scan_result['timestamp']
            for port_info in scan_result['ports']:
                port_info = self._convert_datetime(port_info)
                port_info['ip_address'] = ip
                port_info['scan_time'] = datetime.fromtimestamp(timestamp).isoformat()
                cursor.execute('''
                    INSERT OR REPLACE INTO port_scanning (ip_address, port, protocol, service, is_open, scan_time)
                    VALUES (:ip_address, :port, :protocol, :service, :is_open, :scan_time)
                ''', port_info)
            self.connection.commit()
        except Exception as e:
            logger.error(f"Ошибка при сохранении сканирования портов для {scan_result.get('ip', 'unknown')}: {str(e)}")
        finally:
            cursor.close()

    def get_last_port_scan(self, ip: str) -> Dict[str, Any]:
        cursor = self.connection.cursor()
        try:
            cursor.execute('SELECT * FROM port_scanning WHERE ip_address = ?', (ip,))
            rows = cursor.fetchall()
            if rows:
                ports = [dict(row) for row in rows]
                latest_time = max(row['scan_time'] for row in ports if row['scan_time'])
                return {"ip": ip, "ports": [p for p in ports if p['scan_time'] == latest_time], "timestamp": datetime.fromisoformat(latest_time).timestamp()}
            return {}
        except Exception as e:
            logger.error(f"Ошибка при получении последнего сканирования портов для {ip}: {str(e)}")
            return {}
        finally:
            cursor.close()

    def save_dns_record(self, record: Dict[str, Any]) -> None:
        cursor = self.connection.cursor()
        try:
            record = self._convert_datetime(record)
            cursor.execute('''
                INSERT OR REPLACE INTO dns_monitoring (domain, record_type, value, ttl, check_time)
                VALUES (:domain, :record_type, :value, :ttl, :check_time)
            ''', record)
            self.connection.commit()
        except Exception as e:
            logger.error(f"Ошибка при сохранении DNS-записи для {record.get('domain', 'unknown')}: {str(e)}")
        finally:
            cursor.close()

    def get_dns_records(self, domain: str) -> List[Dict[str, Any]]:
        cursor = self.connection.cursor()
        try:
            cursor.execute('SELECT * FROM dns_monitoring WHERE domain = ?', (domain,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Ошибка при получении DNS-записей для {domain}: {str(e)}")
            return []
        finally:
            cursor.close()

    def save_security_headers(self, headers_info: Dict[str, Any]) -> None:
        cursor = self.connection.cursor()
        try:
            headers_info = self._convert_datetime(headers_info)
            cursor.execute('''
                INSERT OR REPLACE INTO security_headers (url, header_name, header_value, check_time)
                VALUES (:url, :header_name, :header_value, :check_time)
            ''', headers_info)
            self.connection.commit()
        except Exception as e:
            logger.error(f"Ошибка при сохранении заголовков безопасности для {headers_info.get('url', 'unknown')}: {str(e)}")
        finally:
            cursor.close()

    def get_security_headers(self, url: str) -> List[Dict[str, Any]]:
        cursor = self.connection.cursor()
        try:
            cursor.execute('SELECT * FROM security_headers WHERE url = ?', (url,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Ошибка при получении заголовков безопасности для {url}: {str(e)}")
            return []
        finally:
            cursor.close()

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
                for key in ['scan_time', 'check_time', 'not_before', 'not_after']:
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

    def delete_ip_state(self, ip_address: str) -> bool:
        cursor = self.connection.cursor()
        try:
            cursor.execute('DELETE FROM ip_states WHERE ip_address = ?', (ip_address,))
            self.connection.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Ошибка при удалении IP {ip_address}: {str(e)}")
            return False
        finally:
            cursor.close()

    def delete_website_state(self, url: str) -> bool:
        cursor = self.connection.cursor()
        try:
            cursor.execute('DELETE FROM website_states WHERE url = ?', (url,))
            self.connection.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Ошибка при удалении сайта {url}: {str(e)}")
            return False
        finally:
            cursor.close()

    def delete_cert_info(self, domain: str) -> bool:
        cursor = self.connection.cursor()
        try:
            cursor.execute('DELETE FROM ssl_certificates WHERE domain = ?', (domain,))
            self.connection.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Ошибка при удалении сертификата {domain}: {str(e)}")
            return False
        finally:
            cursor.close()

    def delete_port_state(self, ip_address: str) -> bool:
        cursor = self.connection.cursor()
        try:
            cursor.execute('DELETE FROM port_scanning WHERE ip_address = ?', (ip_address,))
            self.connection.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Ошибка при удалении портов для {ip_address}: {str(e)}")
            return False
        finally:
            cursor.close()

    def delete_dns_records(self, domain: str) -> bool:
        cursor = self.connection.cursor()
        try:
            cursor.execute('DELETE FROM dns_monitoring WHERE domain = ?', (domain,))
            self.connection.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Ошибка при удалении DNS-записей для {domain}: {str(e)}")
            return False
        finally:
            cursor.close()

    def delete_security_headers(self, url: str) -> bool:
        cursor = self.connection.cursor()
        try:
            cursor.execute('DELETE FROM security_headers WHERE url = ?', (url,))
            self.connection.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Ошибка при удалении заголовков безопасности для {url}: {str(e)}")
            return False
        finally:
            cursor.close()

    def close(self):
        self.connection.close()