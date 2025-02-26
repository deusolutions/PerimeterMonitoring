#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import dns.resolver
import dns.exception
import time
import logging
from typing import List, Dict, Any, Tuple, Set, Optional
import json

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DNSMonitor:
    def __init__(self, database, config):
        """
        Инициализация монитора DNS
        
        Args:
            database: Объект для работы с БД
            config: Объект с конфигурацией
        """
        self.database = database
        self.config = config
        self.timeout = config.getfloat('dns_monitor', 'timeout', fallback=3.0)
        self.record_types = self._load_record_types()
        self.nameservers = self._load_nameservers()
        
        # Создаем резолвер с указанными DNS-серверами, если они заданы
        self.resolver = dns.resolver.Resolver()
        if self.nameservers:
            self.resolver.nameservers = self.nameservers
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout * 2
        
    def _load_record_types(self) -> List[str]:
        """Загружает список типов DNS-записей из конфигурации"""
        try:
            types_str = self.config.get('dns_monitor', 'record_types', fallback='A,AAAA,MX,NS,TXT,CNAME,SOA')
            return [rtype.strip() for rtype in types_str.split(',')]
        except Exception as e:
            logger.error(f"Ошибка при загрузке типов DNS-записей: {e}")
            # Возвращаем стандартные типы записей
            return ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
            
    def _load_nameservers(self) -> List[str]:
        """Загружает список DNS-серверов из конфигурации"""
        try:
            ns_str = self.config.get('dns_monitor', 'nameservers', fallback='')
            if ns_str:
                return [ns.strip() for ns in ns_str.split(',')]
            return []
        except Exception as e:
            logger.error(f"Ошибка при загрузке DNS-серверов: {e}")
            return []
    
    def get_dns_records(self, domain: str) -> Dict[str, Any]:
        """
        Получает все DNS-записи для указанного домена
        
        Args:
            domain: Доменное имя для проверки
            
        Returns:
            Dict с информацией о DNS-записях
        """
        result = {
            "domain": domain,
            "timestamp": time.time(),
            "records": {}
        }
        
        for record_type in self.record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                records = []
                
                for rdata in answers:
                    if record_type == 'A' or record_type == 'AAAA':
                        records.append(str(rdata))
                    elif record_type == 'MX':
                        records.append({
                            'preference': rdata.preference,
                            'exchange': str(rdata.exchange)
                        })
                    elif record_type == 'SOA':
                        records.append({
                            'mname': str(rdata.mname),
                            'rname': str(rdata.rname),
                            'serial': rdata.serial,
                            'refresh': rdata.refresh,
                            'retry': rdata.retry,
                            'expire': rdata.expire,
                            'minimum': rdata.minimum
                        })
                    elif record_type == 'NS' or record_type == 'CNAME' or record_type == 'PTR':
                        records.append(str(rdata.target))
                    elif record_type == 'TXT':
                        txt_data = b''.join(rdata.strings).decode('utf-8', errors='ignore')
                        records.append(txt_data)
                    else:
                        records.append(str(rdata))
                
                if records:
                    result["records"][record_type] = records
                    
            except dns.resolver.NoAnswer:
                logger.debug(f"Нет записей типа {record_type} для домена {domain}")
            except dns.resolver.NXDOMAIN:
                logger.warning(f"Домен {domain} не существует")
                result["error"] = "NXDOMAIN"
                break
            except dns.exception.Timeout:
                logger.warning(f"Тайм-аут DNS при запросе {record_type} записей для {domain}")
                result["error"] = f"DNS timeout for {record_type}"
            except Exception as e:
                logger.error(f"Ошибка при получении {record_type} записей для {domain}: {e}")
                result["error"] = f"Error for {record_type}: {str(e)}"
        
        # Добавляем TTL информацию для A записей, если они есть
        if 'A' in result["records"]:
            try:
                answer = self.resolver.resolve(domain, 'A')
                result["ttl"] = answer.ttl
            except Exception as e:
                logger.debug(f"Не удалось получить TTL для {domain}: {e}")
                
        return result
    
    def check_changes(self, domain: str, current_data: Dict[str, Any]) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Проверяет изменения DNS-записей по сравнению с предыдущим сканированием
        
        Args:
            domain: Доменное имя
            current_data: Текущие данные DNS
            
        Returns:
            Tuple[bool, List[Dict]]: Флаг наличия изменений и список изменений
        """
        changes = []
        previous_data = self.database.get_last_dns_scan(domain)
        
        if not previous_data or "error" in previous_data:
            # Первое успешное сканирование - считаем всё новым
            if "records" in current_data and current_data["records"]:
                changes.append({
                    "type": "initial",
                    "message": f"Первоначальное сканирование DNS для {domain}"
                })
            return bool(changes), changes
        
        # Сравниваем текущие и предыдущие записи
        prev_records = previous_data.get("records", {})
        curr_records = current_data.get("records", {})
        
        # Проверяем новые типы записей
        for record_type in curr_records:
            if record_type not in prev_records:
                changes.append({
                    "type": "new_record_type",
                    "record_type": record_type,
                    "message": f"Новый тип DNS-записи {record_type} для {domain}"
                })
                continue
                
            # Сравниваем записи одного типа
            current_set = self._convert_to_comparable(curr_records[record_type])
            previous_set = self._convert_to_comparable(prev_records[record_type])
            
            # Новые записи
            new_records = current_set - previous_set
            if new_records:
                changes.append({
                    "type": "new_records",
                    "record_type": record_type,
                    "records": list(new_records),
                    "message": f"Новые записи типа {record_type} для {domain}"
                })
                
            # Удаленные записи
            removed_records = previous_set - current_set
            if removed_records:
                changes.append({
                    "type": "removed_records",
                    "record_type": record_type,
                    "records": list(removed_records),
                    "message": f"Удалены записи типа {record_type} для {domain}"
                })
        
        # Проверяем удаленные типы записей
        for record_type in prev_records:
            if record_type not in curr_records:
                changes.append({
                    "type": "removed_record_type",
                    "record_type": record_type,
                    "message": f"Удален тип DNS-записи {record_type} для {domain}"
                })
        
        # Проверяем изменение TTL, если доступно
        if "ttl" in current_data and "ttl" in previous_data and current_data["ttl"] != previous_data["ttl"]:
            changes.append({
                "type": "ttl_changed",
                "old_ttl": previous_data["ttl"],
                "new_ttl": current_data["ttl"],
                "message": f"Изменился TTL для {domain}: {previous_data['ttl']} -> {current_data['ttl']}"
            })
            
        return bool(changes), changes
        
    def _convert_to_comparable(self, records: List) -> Set[str]:
        """
        Преобразует список записей в множество строк для сравнения
        
        Args:
            records: Список DNS-записей
            
        Returns:
            Set[str]: Множество записей в виде строк
        """
        result = set()
        for record in records:
            if isinstance(record, dict):
                # Преобразуем словарь в строку для сравнения
                record_str = json.dumps(record, sort_keys=True)
                result.add(record_str)
            else:
                result.add(str(record))
        return result
    
    def monitor_domains(self, domain_list: List[str]) -> List[Dict[str, Any]]:
        """
        Запускает мониторинг списка доменов
        
        Args:
            domain_list: Список доменов для мониторинга
            
        Returns:
            List[Dict]: Список отчетов о найденных изменениях
        """
        reports = []
        
        for domain in domain_list:
            logger.info(f"Мониторинг DNS-записей для {domain}")
            try:
                # Получаем данные DNS
                dns_data = self.get_dns_records(domain)
                
                # Если произошла ошибка NXDOMAIN, создаем соответствующую запись изменений
                if "error" in dns_data and dns_data["error"] == "NXDOMAIN":
                    previous_data = self.database.get_last_dns_scan(domain)
                    if previous_data and "error" not in previous_data:
                        report = {
                            "domain": domain,
                            "timestamp": time.time(),
                            "changes": [{
                                "type": "domain_not_found",
                                "message": f"Домен {domain} больше не существует (NXDOMAIN)"
                            }]
                        }
                        reports.append(report)
                        logger.warning(f"Домен {domain} больше не существует")
                    
                    self.database.save_dns_scan(dns_data)
                    continue
                
                # Проверяем изменения
                has_changes, changes = self.check_changes(domain, dns_data)
                
                # Сохраняем результаты в БД
                self.database.save_dns_scan(dns_data)
                
                # Если есть изменения, добавляем отчет
                if has_changes:
                    report = {
                        "domain": domain,
                        "timestamp": dns_data["timestamp"],
                        "changes": changes
                    }
                    reports.append(report)
                    logger.info(f"Обнаружены изменения в DNS для {domain}: {len(changes)} изменений")
                else:
                    logger.info(f"Изменений в DNS для {domain} не обнаружено")
                    
            except Exception as e:
                logger.error(f"Ошибка при мониторинге DNS для {domain}: {e}")
        
        return reports
    
    def check_domain_takeover(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Проверяет возможность захвата домена (domain takeover)
        
        Args:
            domain: Доменное имя для проверки
            
        Returns:
            Optional[Dict]: Данные о потенциальном захвате домена или None
        """
        try:
            # Получаем CNAME записи
            cname_data = None
            try:
                answers = self.resolver.resolve(domain, 'CNAME')
                for rdata in answers:
                    cname_data = str(rdata.target)
                    break
            except dns.resolver.NoAnswer:
                return None
            except Exception as e:
                logger.debug(f"Ошибка при получении CNAME для {domain}: {e}")
                return None
                
            if not cname_data:
                return None
                
            # Проверяем, указывает ли CNAME на несуществующий домен
            try:
                self.resolver.resolve(cname_data, 'A')
                # Если мы здесь - значит домен существует
                return None
            except dns.resolver.NXDOMAIN:
                # Домен из CNAME не существует - потенциальная возможность захвата
                result = {
                    "domain": domain,
                    "cname_target": cname_data,
                    "timestamp": time.time(),
                    "vulnerability": "possible_domain_takeover",
                    "message": f"Домен {domain} имеет CNAME на несуществующий домен {cname_data}. Возможен захват домена."
                }
                logger.warning(f"Возможность захвата домена {domain} через CNAME -> {cname_data}")
                return result
            except Exception:
                return None
                
        except Exception as e:
            logger.error(f"Ошибка при проверке захвата домена {domain}: {e}")
            return None

if __name__ == "__main__":
    # Тестирование модуля
    import sys
    
    if len(sys.argv) < 2:
        print("Использование: python dns_monitor.py <domain>")
        sys.exit(1)
    
    # Простая заглушка для тестирования
    class MockConfig:
        def get(self, section, option, fallback=None):
            return fallback
            
        def getfloat(self, section, option, fallback=None):
            return fallback
    
    class MockDatabase:
        def get_last_dns_scan(self, domain):
            return None
            
        def save_dns_scan(self, dns_data):
            print(f"Сохранено в БД: {json.dumps(dns_data, indent=2)}")
    
    monitor = DNSMonitor(MockDatabase(), MockConfig())
    result = monitor.get_dns_records(sys.argv[1])
    
    print(f"Результаты DNS-мониторинга для {sys.argv[1]}:")
    print(json.dumps(result, indent=2))
    
    # Проверка на возможность захвата домена
    takeover = monitor.check_domain_takeover(sys.argv[1])
    if takeover:
        print("\nВНИМАНИЕ! Обнаружена возможность захвата домена:")
        print(json.dumps(takeover, indent=2))