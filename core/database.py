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
        self.db_name = "monitoring.db"
        self.connection = None
        
    def initialize(self) -> None:
        """
        Инициализация соединения с базой данных и создание необходимых таблиц
        """
        try:
            self.connection = sqlite3.connect(self.db_name, check_same_thread=False)
            # Настройка SQLite для использования dict в качестве формата строк
            self.connection.row_factory = sqlite3.Row
            
            # Создание необходимых таблиц
            self._create_tables()
            
            logger.info(f"База данных {self.db_name} инициализирована")
        except Exception as e:
            logger.error(f"Ошибка при инициализации базы данных: {str(e)}")
            raise
    
    def _create_tables(self) -> None:
        """
        Создание необходимых таблиц в базе данных
        """
        cursor = self.connection.cursor()
        
        # Таблица для IP-адресов
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_states (
            ip_address TEXT PRIMARY KEY,
            is_up INTEGER,
            hostname TEXT,
            scan_time TEXT,
            data TEXT
        )
        ''')
        
        # Таблица для истории изменений IP
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            old_state TEXT,
            new_state TEXT,
            change_time TEXT
        )
        ''')
        
        # Таблица для состояния веб-сайтов
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
        
        # Таблица для истории изменений состояния веб-сайтов
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS website_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            old_state TEXT,
            new_state TEXT,
            change_time TEXT
        )
        ''')
        
        # Таблица для информации о сертификатах
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
        
        # Таблица для открытых портов
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
        
        # Таблица для DNS-записей
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
        
        # Таблица для истории изменений DNS
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
        
        # Таблица для заголовков безопасности
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
        """
        Сохранение состояния IP-адреса
        
        Args:
            state: Состояние IP-адреса
        """
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
        """
        Получение состояния IP-адреса
        
        Args:
            ip_address: IP-адрес
            
        Returns:
            Optional[Dict]: Состояние IP-адреса или None, если не найдено
        """
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
        """
        Сохранение изменения IP-адреса
        
        Args:
            change: Информация об изменении
        """
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
        """
        Сохранение состояния веб-сайта
        
        Args:
            state: Состояние веб-сайта
        """
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
        """
        Получение состояния веб-сайта
        
        Args:
            url: URL веб-сайта
            
        Returns:
            Optional[Dict]: Состояние веб-сайта или None, если не найдено
        """
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
        """
        Сохранение изменения состояния веб-сайта
        
        Args:
            change: Информация об изменении
        """
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
        """
        Сохранение информации о сертификате
        
        Args:
            cert_info: Информация о сертификате
        """
        cursor = self.connection.cursor()
        
        try:
            # Преобразование datetime в строку
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
        """
        Получение информации о сертификате
        
        Args:
            domain: Доменное имя
            
        Returns:
            Optional[Dict]: Информация о сертификате или None, если не найдено
        """
        cursor = self.connection.cursor()
        
        try:
            cursor.execute('SELECT data FROM cert_info WHERE domain = ?', (domain,))
            row = cursor.fetchone()
            
            if row:
                cert_info = json.loads(row[0])
                
                # Преобразование строк обратно в datetime
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
    
    def close(self) -> None:
        """
        Закрытие соединения с базой данных
        """
        if self.connection:
            self.connection.close()
            logger.info("Соединение с базой данных закрыто")