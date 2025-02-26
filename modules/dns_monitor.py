import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

import dns.resolver
from core.database import Database
from core.notification import NotificationManager
import time
import config

logger = logging.getLogger("DNSMonitor")

class DNSMonitor:
    def __init__(self, db: Database, notifier: NotificationManager, config):
        self.db = db
        self.notifier = notifier
        self.enabled = config.DNS_MONITOR_ENABLED
        self.timeout = config.DNS_TIMEOUT
        try:
            self.record_types = config.DNS_RECORD_TYPES
        except AttributeError:
            logger.error("Ошибка при загрузке типов DNS-записей")
            self.record_types = ['A', 'AAAA', 'MX', 'NS']  # Значения по умолчанию
        self.nameservers = config.DNS_NAMESERVERS if config.DNS_NAMESERVERS else None
        self.resolver = dns.resolver.Resolver()
        if self.nameservers:
            self.resolver.nameservers = self.nameservers

    def check_all(self, domains: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        if not self.enabled:
            logger.info("Мониторинг DNS отключен")
            return []
        if domains is None:
            websites = config.WEBSITES
            domains = [url.split('://')[-1].split('/')[0] for url in websites]
        changes = []
        for domain in domains:
            logger.info(f"Мониторинг DNS-записей для {domain}")
            try:
                dns_data = self._check_dns(domain)
                previous = self.db.get_last_dns_scan(domain)
                if previous and self._detect_changes(previous, dns_data):
                    changes.append(dns_data)
                    self._notify_change(domain, previous["records"], dns_data["records"])
                self.db.save_dns_scan(dns_data)
                if changes:
                    logger.info(f"Обнаружены изменения в DNS для {domain}: {len(changes)} изменений")
                else:
                    logger.info(f"Изменений в DNS для {domain} не обнаружено")
            except Exception as e:
                logger.error(f"Ошибка при проверке DNS для {domain}: {str(e)}")
        return changes

    def _check_dns(self, domain: str) -> Dict[str, Any]:
        records = {}
        for rtype in self.record_types:
            try:
                answers = self.resolver.resolve(domain, rtype, lifetime=self.timeout)
                records[rtype] = [str(rdata) for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                records[rtype] = []
            except Exception as e:
                logger.debug(f"Ошибка при запросе {rtype} для {domain}: {str(e)}")
                records[rtype] = []
        return {
            "domain": domain,
            "records": records,
            "ttl": 0,  # TTL можно добавить через answers.rrset.ttl, если нужно
            "timestamp": time.time()
        }

    def _detect_changes(self, previous: Dict[str, Any], current: Dict[str, Any]) -> bool:
        return previous["records"] != current["records"]

    def _notify_change(self, domain: str, old_records: Dict[str, List[str]], new_records: Dict[str, List[str]]) -> None:
        title = f"ℹ️ Изменения в DNS для {domain}"
        message = f"Обнаружены изменения в DNS-записях для {domain}:\n"
        for rtype in set(old_records.keys()) | set(new_records.keys()):
            old = old_records.get(rtype, [])
            new = new_records.get(rtype, [])
            if old != new:
                message += f"{rtype}: было {old}, стало {new}\n"
        self.notifier.send_notification(title, message)