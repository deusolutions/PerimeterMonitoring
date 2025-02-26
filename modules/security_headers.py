#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import time
import logging
import json
from typing import Dict, Any, List, Tuple, Optional
from urllib3.exceptions import InsecureRequestWarning
import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SecurityHeadersChecker:
    def __init__(self, database, config):
        self.database = database
        self.config = config
        self.timeout = getattr(config, 'SECURITY_HEADERS_TIMEOUT', 10.0)
        self.user_agent = getattr(config, 'SECURITY_HEADERS_USER_AGENT', 
                                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36')
        self.verify_ssl = getattr(config, 'SECURITY_HEADERS_VERIFY_SSL', False)
        self.critical_headers = self._load_critical_headers()
        self.recommended_headers = self._load_recommended_headers()
        self.expected_values = self._load_expected_values()
        
    def _load_critical_headers(self) -> List[str]:
        try:
            return self.config.SECURITY_HEADERS  # Используем из config.py
        except Exception as e:
            logger.error(f"Ошибка при загрузке критических заголовков: {e}")
            return ['Strict-Transport-Security', 'X-XSS-Protection', 'X-Frame-Options', 'X-Content-Type-Options']
    
    def _load_recommended_headers(self) -> List[str]:
        try:
            return ['Content-Security-Policy', 'Referrer-Policy', 'Feature-Policy', 'Permissions-Policy']
        except Exception as e:
            logger.error(f"Ошибка при загрузке рекомендуемых заголовков: {e}")
            return ['Content-Security-Policy', 'Referrer-Policy', 'Feature-Policy', 'Permissions-Policy']
    
    def _load_expected_values(self) -> Dict[str, Dict[str, Any]]:
        default_values = {
            'Strict-Transport-Security': {'min_max_age': 15552000, 'include_subdomains': True},
            'X-XSS-Protection': {'valid_values': ['1', '1; mode=block']},
            'X-Frame-Options': {'valid_values': ['DENY', 'SAMEORIGIN']},
            'X-Content-Type-Options': {'valid_values': ['nosniff']},
            'Referrer-Policy': {'recommended_values': ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin']}
        }
        try:
            custom_values_str = getattr(self.config, 'SECURITY_HEADERS_EXPECTED_VALUES', '')
            if custom_values_str:
                custom_values = json.loads(custom_values_str)
                for header, values in custom_values.items():
                    if header in default_values:
                        default_values[header].update(values)
                    else:
                        default_values[header] = values
        except Exception as e:
            logger.error(f"Ошибка при загрузке ожидаемых значений заголовков: {e}")
        return default_values
    
    def check_url(self, url: str) -> Dict[str, Any]:
        result = {
            "url": url,
            "timestamp": time.time(),
            "headers": {},
            "missing_critical": [],
            "missing_recommended": [],
            "issues": []
        }
        try:
            headers = {'User-Agent': self.user_agent}
            response = requests.get(url, headers=headers, timeout=self.timeout, verify=self.verify_ssl, allow_redirects=True)
            result["status_code"] = response.status_code
            result["response_time"] = response.elapsed.total_seconds()
            all_headers = {k: v for k, v in response.headers.items()}
            result["headers"] = all_headers
            for header in self.critical_headers:
                if header not in response.headers:
                    result["missing_critical"].append(header)
                    result["issues"].append({"type": "missing_critical_header", "header": header, "severity": "high", "message": f"Отсутствует критически важный заголовок безопасности: {header}"})
                elif header in self.expected_values:
                    self._check_header_value(header, response.headers[header], result)
            for header in self.recommended_headers:
                if header not in response.headers:
                    result["missing_recommended"].append(header)
                    result["issues"].append({"type": "missing_recommended_header", "header": header, "severity": "medium", "message": f"Отсутствует рекомендуемый заголовок безопасности: {header}"})
                elif header in self.expected_values:
                    self._check_header_value(header, response.headers[header], result)
            if url.startswith('http://'):
                result["issues"].append({"type": "not_using_https", "severity": "high", "message": "Сайт не использует HTTPS"})
            result["security_score"] = self._calculate_security_score(result)
        except requests.exceptions.SSLError as e:
            result["error"] = f"SSL Error: {str(e)}"
            logger.error(f"SSL-ошибка при проверке {url}: {e}")
        except requests.exceptions.RequestException as e:
            result["error"] = f"Request Error: {str(e)}"
            logger.error(f"Ошибка запроса при проверке {url}: {e}")
        except Exception as e:
            result["error"] = f"Error: {str(e)}"
            logger.error(f"Ошибка при проверке заголовков для {url}: {e}")
        return result
    
    def _check_header_value(self, header: str, value: str, result: Dict[str, Any]) -> None:
        expected = self.expected_values.get(header, {})
        if header == 'Strict-Transport-Security':
            min_max_age = expected.get('min_max_age', 15552000)
            include_subdomains = expected.get('include_subdomains', True)
            max_age_value = None
            has_subdomains = False
            for part in value.split(';'):
                part = part.strip()
                if part.startswith('max-age='):
                    try:
                        max_age_value = int(part.split('=')[1])
                    except (ValueError, IndexError):
                        pass
                elif part == 'includeSubDomains':
                    has_subdomains = True
            if max_age_value is None:
                result["issues"].append({"type": "invalid_header_value", "header": header, "value": value, "severity": "medium", "message": f"Заголовок {header} не содержит корректного значения max-age"})
            elif max_age_value < min_max_age:
                result["issues"].append({"type": "insecure_header_value", "header": header, "value": value, "severity": "medium", "message": f"Заголовок {header} имеет слишком короткое значение max-age: {max_age_value} (рекомендуется минимум {min_max_age})"})
            if include_subdomains and not has_subdomains:
                result["issues"].append({"type": "incomplete_header_value", "header": header, "value": value, "severity": "low", "message": f"Заголовок {header} не включает директиву includeSubDomains"})
        elif 'valid_values' in expected:
            valid_values = expected['valid_values']
            if value not in valid_values:
                result["issues"].append({"type": "invalid_header_value", "header": header, "value": value, "severity": "medium", "message": f"Заголовок {header} имеет недопустимое значение: {value}. Ожидаемые значения: {', '.join(valid_values)}"})
        elif 'recommended_values' in expected:
            recommended_values = expected['recommended_values']
            if value not in recommended_values:
                result["issues"].append({"type": "suboptimal_header_value", "header": header, "value": value, "severity": "low", "message": f"Заголовок {header} имеет значение, отличное от рекомендуемых: {value}. Рекомендуемые значения: {', '.join(recommended_values)}"})
    
    def _calculate_security_score(self, result: Dict[str, Any]) -> int:
        score = 100
        score -= len(result["missing_critical"]) * 15
        score -= len(result["missing_recommended"]) * 5
        for issue in result["issues"]:
            if issue["type"] == "not_using_https":
                score -= 30
            elif issue["severity"] == "high":
                score -= 10
            elif issue["severity"] == "medium":
                score -= 5
            elif issue["severity"] == "low":
                score -= 2
        return max(0, min(100, score))
    
    def check_changes(self, url: str, current_data: Dict[str, Any]) -> Tuple[bool, List[Dict[str, Any]]]:
        changes = []
        previous_data = self.database.get_last_security_headers_check(url)
        if not previous_data or "error" in previous_data:
            if "headers" in current_data and current_data["headers"]:
                changes.append({"type": "initial", "message": f"Первоначальная проверка заголовков безопасности для {url}"})
            return bool(changes), changes
        prev_headers = previous_data.get("headers", {})
        curr_headers = current_data.get("headers", {})
        for header, value in curr_headers.items():
            if header not in prev_headers:
                if header in self.critical_headers or header in self.recommended_headers:
                    changes.append({"type": "new_security_header", "header": header, "value": value, "message": f"Добавлен новый заголовок безопасности: {header}: {value}"})
                else:
                    changes.append({"type": "new_header", "header": header, "value": value, "message": f"Добавлен новый заголовок: {header}: {value}"})
        for header, value in prev_headers.items():
            if header not in curr_headers:
                if header in self.critical_headers:
                    changes.append({"type": "removed_critical_header", "header": header, "old_value": value, "message": f"Удален критический заголовок безопасности: {header}"})
                elif header in self.recommended_headers:
                    changes.append({"type": "removed_recommended_header", "header": header, "old_value": value, "message": f"Удален рекомендуемый заголовок безопасности: {header}"})
                else:
                    changes.append({"type": "removed_header", "header": header, "old_value": value, "message": f"Удален заголовок: {header}"})
        for header, curr_value in curr_headers.items():
            if header in prev_headers and prev_headers[header] != curr_value:
                if header in self.critical_headers or header in self.recommended_headers:
                    changes.append({"type": "changed_security_header", "header": header, "old_value": prev_headers[header], "new_value": curr_value, "message": f"Изменено значение заголовка безопасности {header}: {prev_headers[header]} -> {curr_value}"})
                else:
                    changes.append({"type": "changed_header", "header": header, "old_value": prev_headers[header], "new_value": curr_value, "message": f"Изменено значение заголовка {header}: {prev_headers[header]} -> {curr_value}"})
        if "security_score" in current_data and "security_score" in previous_data:
            curr_score = current_data["security_score"]
            prev_score = previous_data["security_score"]
            if curr_score != prev_score:
                changes.append({"type": "security_score_changed", "old_score": prev_score, "new_score": curr_score, "difference": curr_score - prev_score, "message": f"Изменилась оценка безопасности заголовков: {prev_score} -> {curr_score}"})
        return bool(changes), changes
    
    def check_all(self, url_list: List[str]) -> List[Dict[str, Any]]:  # Переименован из check_websites
        reports = []
        for url in url_list:
            logger.info(f"Проверка заголовков безопасности для {url}")
            try:
                check_result = self.check_url(url)
                if "error" in check_result:
                    logger.warning(f"Ошибка при проверке заголовков для {url}: {check_result['error']}")
                    self.database.save_security_headers_check(check_result)
                    continue
                has_changes, changes = self.check_changes(url, check_result)
                self.database.save_security_headers_check(check_result)
                if has_changes or any(issue["severity"] == "high" for issue in check_result.get("issues", [])):
                    report = {
                        "url": url,
                        "timestamp": check_result["timestamp"],
                        "changes": changes,
                        "issues": check_result.get("issues", []),
                        "security_score": check_result.get("security_score", 0)
                    }
                    reports.append(report)
                    logger.info(f"Обнаружены изменения в заголовках для {url}: {len(changes)} изменений")
                else:
                    logger.info(f"Изменений в заголовках для {url} не обнаружено")
            except Exception as e:
                logger.error(f"Ошибка при проверке заголовков для {url}: {e}")
        return reports

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Использование: python security_headers.py <url>")
        sys.exit(1)
    class MockConfig:
        def get(self, section, option, fallback=None):
            return fallback
        def getfloat(self, section, option, fallback=None):
            return fallback
        def getboolean(self, section, option, fallback=None):
            return fallback
    class MockDatabase:
        def get_last_security_headers_check(self, url):
            return None
        def save_security_headers_check(self, check_data):
            print(f"Сохранено в БД: {json.dumps(check_data, indent=2)}")
    checker = SecurityHeadersChecker(MockDatabase(), MockConfig())
    result = checker.check_url(sys.argv[1])
    print(f"Результаты проверки заголовков безопасности для {sys.argv[1]}:")
    print(json.dumps(result, indent=2))