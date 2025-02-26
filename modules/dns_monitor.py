#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import dns.resolver
import dns.exception
import time
import logging
from typing import List, Dict, Any, Tuple, Set, Optional
import json

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DNSMonitor:
    def __init__(self, database, config):
        self.database = database
        self.config = config
        self.timeout = getattr(config, 'DNS_TIMEOUT', 3.0)
        self.record_types = self._load_record_types()
        self.nameservers = self._load_nameservers()
        self.resolver = dns.resolver.Resolver()
        if self.nameservers:
            self.resolver.nameservers = self.nameservers
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout * 2
        
    def _load_record_types(self) -> List[str]:
        try:
            return self.config.DNS_RECORD_TYPES
        except Exception as e:
            logger.error(f"Ошибка при загрузке типов DNS-записей: {e}")
            return ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
            
    def _load_nameservers(self) -> List[str]:
        try:
            return getattr(self.config, 'DNS_NAMESERVERS', [])
        except Exception as e:
            logger.error(f"Ошибка при загрузке DNS-серверов: {e}")
            return []
    
    def get_dns_records(self, domain: str) -> Dict[str, Any]:
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
                    if record_type in ('A', 'AAAA'):
                        records.append(str(rdata))
                    elif record_type == 'MX':
                        records.append({'preference': rdata.preference, 'exchange': str(rdata.exchange)})
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
                    elif record_type in ('NS', 'CNAME', 'PTR'):
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
        if 'A' in result["records"]:
            try:
                answer = self.resolver.resolve(domain, 'A')
                result["ttl"] = answer.ttl
            except Exception as e:
                logger.debug(f"Не удалось получить TTL для {domain}: {e}")
        return result
    
    def check_changes(self, domain: str, current_data: Dict[str, Any]) -> Tuple[bool, List[Dict[str, Any]]]:
        changes = []
        previous_data = self.database.get_last_dns_scan(domain)
        if not previous_data or "error" in previous_data:
            if "records" in current_data and current_data["records"]:
                changes.append({"type": "initial", "message": f"Первоначальное сканирование DNS для {domain}"})
            return bool(changes), changes
        prev_records = previous_data.get("records", {})
        curr_records = current_data.get("records", {})
        for record_type in curr_records:
            if record_type not in prev_records:
                changes.append({"type": "new_record_type", "record_type": record_type, "message": f"Новый тип DNS-записи {record_type} для {domain}"})
                continue
            current_set = self._convert_to_comparable(curr_records[record_type])
            previous_set = self._convert_to_comparable(prev_records[record_type])
            new_records = current_set - previous_set
            if new_records:
                changes.append({"type": "new_records", "record_type": record_type, "records": list(new_records), "message": f"Новые записи типа {record_type} для {domain}"})
            removed_records = previous_set - current_set
            if removed_records:
                changes.append({"type": "removed_records", "record_type": record_type, "records": list(removed_records), "message": f"Удалены записи типа {record_type} для {domain}"})
        for record_type in prev_records:
            if record_type not in curr_records:
                changes.append({"type": "removed_record_type", "record_type": record_type, "message": f"Удален тип DNS-записи {record_type} для {domain}"})
        if "ttl" in current_data and "ttl" in previous_data and current_data["ttl"] != previous_data["ttl"]:
            changes.append({"type": "ttl_changed", "old_ttl": previous_data["ttl"], "new_ttl": current_data["ttl"], "message": f"Изменился TTL для {domain}: {previous_data['ttl']} -> {current_data['ttl']}"})
        return bool(changes), changes
        
    def _convert_to_comparable(self, records: List) -> Set[str]:
        result = set()
        for record in records:
            if isinstance(record, dict):
                record_str = json.dumps(record, sort_keys=True)
                result.add(record_str)
            else:
                result.add(str(record))
        return result
    
    def check_all(self, domain_list: List[str]) -> List[Dict[str, Any]]:  # Переименован из monitor_domains
        reports = []
        for domain in domain_list:
            logger.info(f"Мониторинг DNS-записей для {domain}")
            try:
                dns_data = self.get_dns_records(domain)
                if "error" in dns_data and dns_data["error"] == "NXDOMAIN":
                    previous_data = self.database.get_last_dns_scan(domain)
                    if previous_data and "error" not in previous_data:
                        report = {"domain": domain, "timestamp": time.time(), "changes": [{"type": "domain_not_found", "message": f"Домен {domain} больше не существует (NXDOMAIN)"}]}
                        reports.append(report)
                        logger.warning(f"Домен {domain} больше не существует")
                    self.database.save_dns_scan(dns_data)
                    continue
                has_changes, changes = self.check_changes(domain, dns_data)
                self.database.save_dns_scan(dns_data)
                if has_changes:
                    report = {"domain": domain, "timestamp": dns_data["timestamp"], "changes": changes}
                    reports.append(report)
                    logger.info(f"Обнаружены изменения в DNS для {domain}: {len(changes)} изменений")
                else:
                    logger.info(f"Изменений в DNS для {domain} не обнаружено")
            except Exception as e:
                logger.error(f"Ошибка при мониторинге DNS для {domain}: {e}")
        return reports
    
    def check_domain_takeover(self, domain: str) -> Optional[Dict[str, Any]]:
        try:
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
            try:
                self.resolver.resolve(cname_data, 'A')
                return None
            except dns.resolver.NXDOMAIN:
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
    import sys
    if len(sys.argv) < 2:
        print("Использование: python dns_monitor.py <domain>")
        sys.exit(1)
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
    takeover = monitor.check_domain_takeover(sys.argv[1])
    if takeover:
        print("\nВНИМАНИЕ! Обнаружена возможность захвата домена:")
        print(json.dumps(takeover, indent=2))