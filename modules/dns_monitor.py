# modules/dns_monitor.py
import dns.resolver
import logging
from typing import List, Dict, Any
import time
import config

logger = logging.getLogger(__name__)

class DNSMonitor:
    def __init__(self, db, notifier, config_obj):
        self.db = db
        self.notifier = notifier
        self.enabled = config.DNS_MONITOR_ENABLED
        self.timeout = config.DNS_TIMEOUT
        self.record_types = config.DNS_RECORD_TYPES
        self.nameservers = config.DNS_NAMESERVERS or None

    def _check_dns(self, domain: str) -> List[Dict[str, Any]]:
        if not self.enabled:
            logger.info("Мониторинг DNS отключен")
            return []
        logger.info(f"Мониторинг DNS-записей для {domain}")
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        if self.nameservers:
            resolver.nameservers = self.nameservers
        records = []
        try:
            for rtype in self.record_types:
                try:
                    answers = resolver.resolve(domain, rtype)
                    for rdata in answers:
                        records.append({
                            "domain": domain,
                            "record_type": rtype,
                            "value": str(rdata),
                            "ttl": rdata.ttl if hasattr(rdata, 'ttl') else 0,
                            "check_time": time.time()
                        })
                except dns.resolver.NoAnswer:
                    continue
                except Exception as e:
                    logger.error(f"Ошибка при проверке {rtype} для {domain}: {str(e)}")
            return records
        except Exception as e:
            logger.error(f"Ошибка при проверке DNS для {domain}: {str(e)}")
            return []

    def _detect_change(self, previous: List[Dict[str, Any]], current: List[Dict[str, Any]]) -> bool:
        prev_dict = {(r["record_type"], r["value"]) for r in previous}
        curr_dict = {(r["record_type"], r["value"]) for r in current}
        return prev_dict != curr_dict

    def _notify_change(self, domain: str, changes: List[Dict[str, Any]]) -> None:
        title = f"ℹ️ Изменение DNS-записей для {domain}"
        message = f"Обнаружены изменения в DNS для {domain}:\n"
        for change in changes:
            message += f"{change['record_type']}: {change['value']} (TTL: {change['ttl']})\n"
        self.notifier.send_notification(title, message, priority="high")

    def check_all(self, domains: List[str] = None) -> List[Dict[str, Any]]:
        domains = domains or [r["domain"] for r in self.db.get_all_records("dns_monitoring")]
        changes = []
        for domain in domains:
            current_records = self._check_dns(domain)
            previous_records = self.db.get_dns_records(domain)  # Заменили get_last_dns_scan
            if previous_records and self._detect_change(previous_records, current_records):
                changes.append({"domain": domain, "records": current_records})
                self._notify_change(domain, current_records)
            for record in current_records:
                try:
                    self.db.save_dns_record(record)
                except Exception as e:
                    logger.error(f"Ошибка при сохранении DNS для {domain}: {str(e)}")
            if not current_records:
                logger.info(f"Изменений в DNS для {domain} не обнаружено")
        return changes