"""
modules/monitoring_planner.py
Модуль для планирования системы мониторинга и поддержки (Этап 5)
"""

import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import hashlib

class MonitoringPlanner:
    """Планировщик системы мониторинга и поддержки для Zero Trust IoT"""
    
    def __init__(self, infrastructure: Dict):
        self.infrastructure = infrastructure
        self.devices = infrastructure.get("devices", [])
        self.organization = infrastructure.get("organization", "Неизвестная организация")
        
        # Справочник отечественных решений для мониторинга
        self.domestic_solutions = {
            "siem": [
                {"name": "MaxPatrol SIEM", "vendor": "Positive Technologies", 
                 "features": ["Корреляция событий", "Анализ поведения", "Интеграция с отечественным ПО"]},
                {"name": "Аванпост", "vendor": "Аванпост", 
                 "features": ["Мониторинг безопасности", "Анализ логов", "Соответствие ФСТЭК"]},
                {"name": "Kaspersky Security Center", "vendor": "Лаборатория Касперского",
                 "features": ["Централизованное управление", "Мониторинг угроз", "Автоматизация ответа"]}
            ],
            "soar": [
                {"name": "КиберЛок SOAR", "vendor": "КиберЛок",
                 "features": ["Автоматизация инцидентов", "Playbook", "Интеграция с российскими системами"]},
                {"name": "PT Security Vision", "vendor": "Positive Technologies",
                 "features": ["Управление инцидентами", "Автоматическое реагирование", "Анализ угроз"]}
            ],
            "nta": [
                {"name": "InfoWatch Traffic Monitor", "vendor": "InfoWatch",
                 "features": ["Анализ сетевого трафика", "Выявление аномалий", "DLP функции"]},
                {"name": "Сканер-М", "vendor": "СерчИнформ",
                 "features": ["Мониторинг сети", "Обнаружение вторжений", "Анализ поведения"]}
            ],
            "firmware_verification": [
                {"name": "КриптоПро CSP", "vendor": "КриптоПро",
                 "features": ["Проверка целостности", "Электронная подпись", "Поддержка ГОСТ"]},
                {"name": "ViPNet Validator", "vendor": "ИнфоТеКС",
                 "features": ["Верификация ПО", "Контроль целостности", "Управление ключами"]}
            ]
        }
        
        self.recommendations = {
            "behavioral_analysis": [],      # 5.1 Поведенческий анализ
            "incident_response": [],        # 5.2 Автоматизация ответа на инциденты
            "dynamic_access": [],           # 5.3 Динамическое изменение уровня доступа
            "firmware_verification": [],    # 5.4 Верификация встроенного ПО
            "implementation_plan": [],      # План внедрения
            "integration_requirements": []  # Требования интеграции
        }
    
    def analyze_infrastructure(self) -> Dict:
        """Проанализировать инфраструктуру и сгенерировать рекомендации по мониторингу"""
        print("\n" + "="*80)
        print("ЭТАП 5: АНАЛИЗ И ПЛАНИРОВАНИЕ СИСТЕМЫ МОНИТОРИНГА И ПОДДЕРЖКИ")
        print("="*80)
        
        # 5.1. Поведенческий анализ
        print("\n[5.1] АНАЛИЗ ПОВЕДЕНЧЕСКОГО МОНИТОРИНГА")
        print("-"*40)
        self._analyze_behavioral_monitoring()
        
        # 5.2. Автоматизация ответа на инциденты
        print("\n[5.2] АНАЛИЗ АВТОМАТИЗАЦИИ ОТВЕТА НА ИНЦИДЕНТЫ")
        print("-"*40)
        self._analyze_incident_response()
        
        # 5.3. Динамическое изменение уровня доступа
        print("\n[5.3] АНАЛИЗ ДИНАМИЧЕСКОГО ИЗМЕНЕНИЯ УРОВНЯ ДОСТУПА")
        print("-"*40)
        self._analyze_dynamic_access()
        
        # 5.4. Верификация встроенного ПО
        print("\n[5.4] АНАЛИЗ ВЕРИФИКАЦИИ ВСТРОЕННОГО ПО")
        print("-"*40)
        self._analyze_firmware_verification()
        
        # Генерация плана внедрения
        self._generate_implementation_plan()
        
        return self.recommendations
    
    def _analyze_behavioral_monitoring(self):
        """5.1. Внедрить поведенческий анализ с использованием ИИ"""
        
        # Анализ устройств для определения требований к мониторингу
        for device in self.devices:
            device_id = device["id"]
            device_type = device.get("type", "")
            manufacturer = device.get("manufacturer", "")
            model = device.get("model", "")
            
            # Определяем параметры для поведенческого анализа
            monitoring_params = self._determine_monitoring_parameters(device)
            
            # Генерируем рекомендации по мониторингу
            recommendation = {
                "device_id": device_id,
                "device": f"{manufacturer} {model}",
                "type": device_type,
                "monitoring_level": monitoring_params["level"],
                "key_metrics": monitoring_params["metrics"],
                "anomaly_detection_rules": self._generate_anomaly_rules(device),
                "ai_analysis_requirements": monitoring_params["ai_requirements"],
                "data_collection_methods": self._get_data_collection_methods(device),
                "retention_period": self._get_data_retention_period(device)
            }
            
            self.recommendations["behavioral_analysis"].append(recommendation)
        
        # Общие рекомендации по поведенческому анализу
        general_recommendations = [
            {
                "category": "Методы анализа поведения",
                "techniques": [
                    "Базовый анализ (статистические метрики, пороговые значения)",
                    "Машинное обучение (кластеризация, классификация аномалий)",
                    "Глубокое обучение (нейронные сети для анализа временных рядов)",
                    "Поведенческие профили (создание baseline для каждого устройства)"
                ],
                "tools": ["MaxPatrol SIEM", "Аванпост", "Kaspersky Security Center"]
            },
            {
                "category": "Анализируемые параметры",
                "parameters": [
                    "Сетевой трафик (объем, протоколы, направления)",
                    "Время активности (расписание, аномальные периоды)",
                    "Ресурсы устройства (загрузка CPU, память, дисковое пространство)",
                    "Попытки доступа (успешные/неуспешные, частота, источники)"
                ],
                "implementation": "Внедрение агентов мониторинга или сетевого анализа"
            },
            {
                "category": "Обнаружение сложных атак",
                "scenarios": [
                    "Медленные атаки (low-and-slow), распределенные во времени",
                    "Целевые атаки на конкретные протоколы IoT",
                    "Компрометация через обновления ПО",
                    "Внутренние угрозы (инсайдеры, скомпрометированные учетные записи)"
                ],
                "response": "Автоматическая эскалация в SOAR систему"
            }
        ]
        
        for rec in general_recommendations:
            self.recommendations["behavioral_analysis"].append({
                "type": "Общая рекомендация",
                "category": rec["category"],
                "details": rec
            })
    
    def _determine_monitoring_parameters(self, device: Dict) -> Dict:
        """Определить параметры мониторинга для устройства"""
        device_type = device.get("type", "").lower()
        
        # Базовые метрики для всех устройств
        base_metrics = [
            "Доступность (ping, ответ на запросы)",
            "Загрузка сетевого интерфейса",
            "Количество установленных соединений"
        ]
        
        # Специфические метрики по типу устройства
        specific_metrics = []
        ai_requirements = []
        
        if "камера" in device_type:
            specific_metrics.extend([
                "Битрейт видео потока",
                "Количество кадров в секунду",
                "Активность движения в кадре",
                "Качество видео (размытие, артефакты)"
            ])
            ai_requirements.append("Анализ видео потоков на аномальную активность")
            
        elif "датчик" in device_type:
            specific_metrics.extend([
                "Частота отправки данных",
                "Диапазон значений показаний",
                "Стабильность показаний",
                "Калибровочные смещения"
            ])
            ai_requirements.append("Выявление аномальных показаний с помощью машинного обучения")
            
        elif any(x in device_type for x in ["маршрутизатор", "коммутатор"]):
            specific_metrics.extend([
                "Таблица маршрутизации (изменения)",
                "ARP таблица (новые MAC адреса)",
                "Использование портов",
                "Ошибки CRC, коллизии"
            ])
            ai_requirements.append("Анализ сетевых аномалий и атак")
        
        # Определение уровня мониторинга
        if device.get("kii_category", 0) in [1, 2] or device.get("critical", False):
            level = "ПОЛНЫЙ (все метрики, реальное время, ИИ анализ)"
        elif device.get("data_volume") == "высокая":
            level = "РАСШИРЕННЫЙ (ключевые метрики, периодический ИИ анализ)"
        else:
            level = "БАЗОВЫЙ (минимальные метрики, пороговые значения)"
        
        return {
            "level": level,
            "metrics": base_metrics + specific_metrics,
            "ai_requirements": ai_requirements
        }
    
    def _generate_anomaly_rules(self, device: Dict) -> List[Dict]:
        """Сгенерировать правила обнаружения аномалий для устройства"""
        rules = []
        device_type = device.get("type", "").lower()
        
        # Общие правила
        general_rules = [
            {
                "rule_id": "GEN-001",
                "description": "Устройство недоступно более 5 минут",
                "condition": "Нет ответа на ping/запросы в течение 300 секунд",
                "severity": "ВЫСОКАЯ",
                "action": "Оповещение администратора, создание инцидента"
            },
            {
                "rule_id": "GEN-002",
                "description": "Аномальный рост сетевого трафика",
                "condition": "Трафик превышает среднее значение на 300%",
                "severity": "СРЕДНЯЯ",
                "action": "Анализ источника трафика, временное ограничение"
            }
        ]
        
        rules.extend(general_rules)
        
        # Специфические правила по типу устройства
        if "камера" in device_type:
            rules.extend([
                {
                    "rule_id": "CAM-001",
                    "description": "Камера передает черный/статичный кадр",
                    "condition": "Отсутствие изменений в видео потоке более 60 секунд",
                    "severity": "СРЕДНЯЯ",
                    "action": "Проверка соединения, перезагрузка камеры"
                },
                {
                    "rule_id": "CAM-002",
                    "description": "Несанкционированное изменение направления камеры",
                    "condition": "Изменение PTZ параметров без авторизованной команды",
                    "severity": "ВЫСОКАЯ",
                    "action": "Блокировка управления, оповещение службы безопасности"
                }
            ])
            
        elif "датчик" in device_type:
            rules.extend([
                {
                    "rule_id": "SEN-001",
                    "description": "Показания датчика вне допустимого диапазона",
                    "condition": "Значение выходит за физические пределы датчика",
                    "severity": "ВЫСОКАЯ",
                    "action": "Калибровка, проверка целостности датчика"
                },
                {
                    "rule_id": "SEN-002", 
                    "description": "Резкие скачки показаний",
                    "condition": "Изменение значения более чем на 50% за 1 секунду",
                    "severity": "СРЕДНЯЯ",
                    "action": "Анализ на помехи, проверка питания"
                }
            ])
        
        return rules
    
    def _get_data_collection_methods(self, device: Dict) -> List[Dict]:
        """Определить методы сбора данных для устройства"""
        methods = []
        device_type = device.get("type", "").lower()
        protocols = device.get("protocols", [])
        
        # Агентский метод (если поддерживается)
        if device.get("compute_power") in ["средняя", "высокая"]:
            methods.append({
                "method": "Агент мониторинга",
                "description": "Установка легковесного агента на устройство",
                "protocol": "HTTPS/WebSocket",
                "frequency": "реальное время"
            })
        
        # SNMP мониторинг
        if "SNMP" in protocols or any(x in device_type for x in ["маршрутизатор", "коммутатор"]):
            methods.append({
                "method": "SNMP опрос",
                "description": "Запрос метрик через SNMP v3",
                "protocol": "SNMP",
                "frequency": "60 секунд"
            })
        
        # NetFlow/sFlow для сетевых устройств
        if any(x in device_type for x in ["маршрутизатор", "коммутатор"]):
            methods.append({
                "method": "NetFlow анализ",
                "description": "Анализ сетевых потоков через NetFlow/sFlow",
                "protocol": "NetFlow v9/IPFIX",
                "frequency": "реальное время"
            })
        
        # Пассивный анализ трафика
        methods.append({
            "method": "Пассивный сетевой анализ",
            "description": "Анализ трафика через SPAN/зеркалирование портов",
            "protocol": "Ethernet",
            "frequency": "реальное время"
        })
        
        return methods
    
    def _get_data_retention_period(self, device: Dict) -> Dict:
        """Определить период хранения данных мониторинга"""
        retention = {
            "raw_data": "30 дней",
            "aggregated_data": "1 год", 
            "security_events": "5 лет",
            "incident_records": "10 лет"
        }
        
        # Для устройств КИИ - более длительное хранение
        if device.get("kii_category", 0) in [1, 2]:
            retention = {
                "raw_data": "90 дней",
                "aggregated_data": "3 года",
                "security_events": "10 лет",
                "incident_records": "15 лет"
            }
        
        return retention
    
    def _analyze_incident_response(self):
        """5.2. Автоматизировать ответ на инциденты через SOAR-платформы"""
        
        # Анализ инцидентов для каждого типа устройств
        incident_scenarios = []
        
        for device in self.devices:
            scenarios = self._generate_incident_scenarios(device)
            incident_scenarios.extend(scenarios)
        
        self.recommendations["incident_response"] = incident_scenarios
        
        # Playbook для автоматизации ответа
        playbooks = [
            {
                "playbook_id": "PB-IOT-001",
                "name": "Компрометация IoT устройства",
                "triggers": ["Обнаружение вредоносного трафика", "Несанкционированный доступ"],
                "steps": [
                    "1. Изоляция устройства в карантинной VLAN",
                    "2. Блокировка трафика на межсетевом экране",
                    "3. Снятие дампа памяти и трафика для анализа",
                    "4. Оповещение SOC и ответственного администратора",
                    "5. Запуск процедуры восстановления из backup"
                ],
                "automation_level": "ПОЛНАЯ АВТОМАТИЗАЦИЯ"
            },
            {
                "playbook_id": "PB-IOT-002", 
                "name": "Атака типа DDoS на IoT устройства",
                "triggers": ["Аномально высокий трафик", "Множественные запросы"],
                "steps": [
                    "1. Активация DDoS защиты у провайдера",
                    "2. Ограничение скорости на сетевых устройствах",
                    "3. Перенаправление трафика через scrubbing center",
                    "4. Блокировка источников атаки",
                    "5. Мониторинг восстановления нормальной работы"
                ],
                "automation_level": "ЧАСТИЧНАЯ АВТОМАТИЗАЦИЯ"
            },
            {
                "playbook_id": "PB-IOT-003",
                "name": "Утечка данных с IoT устройства",
                "triggers": ["Несанкционированная передача данных", "Подозрительные внешние соединения"],
                "steps": [
                    "1. Немедленная блокировка исходящего трафика",
                    "2. Анализ объема и направления утечки",
                    "3. Уведомление регуляторов (при необходимости)",
                    "4. Расследование инцидента",
                    "5. Восстановление контроля и усиление защиты"
                ],
                "automation_level": "ЧАСТИЧНАЯ АВТОМАТИЗАЦИЯ"
            }
        ]
        
        self.recommendations["incident_response"].extend([
            {"type": "Playbook", "content": playbook} for playbook in playbooks
        ])
        
        # Интеграции SOAR
        integrations = [
            {
                "system": "SIEM система",
                "purpose": "Получение событий безопасности",
                "protocol": "Syslog, CEF, LEEF",
                "frequency": "реальное время"
            },
            {
                "system": "Система управления сетью",
                "purpose": "Изоляция устройств, изменение конфигурации",
                "protocol": "REST API, SNMP, SSH",
                "frequency": "по требованию"
            },
            {
                "system": "Система инвентаризации",
                "purpose": "Получение информации об устройствах",
                "protocol": "REST API, база данных",
                "frequency": "ежедневно/по изменению"
            },
            {
                "system": "Сервис рассылки уведомлений",
                "purpose": "Оповещение ответственных лиц",
                "protocol": "Email, SMS, Telegram API",
                "frequency": "при инцидентах"
            }
        ]
        
        self.recommendations["incident_response"].append({
            "type": "Интеграции SOAR",
            "integrations": integrations
        })
    
    def _generate_incident_scenarios(self, device: Dict) -> List[Dict]:
        """Сгенерировать сценарии инцидентов для устройства"""
        scenarios = []
        device_type = device.get("type", "").lower()
        
        # Общие сценарии
        base_scenarios = [
            {
                "scenario_id": f"INC-{device['id']}-001",
                "device_id": device["id"],
                "device": f"{device.get('manufacturer')} {device.get('model')}",
                "scenario": "Несанкционированный доступ к устройству",
                "indicators": [
                    "Неизвестный IP адрес в логах доступа",
                    "Множественные неудачные попытки входа",
                    "Изменение конфигурации без утверждения"
                ],
                "response_time": "15 минут" if device.get("critical") else "60 минут",
                "escalation_level": "Уровень 2" if device.get("critical") else "Уровень 3"
            }
        ]
        
        scenarios.extend(base_scenarios)
        
        # Специфические сценарии
        if "камера" in device_type:
            scenarios.append({
                "scenario_id": f"INC-{device['id']}-002",
                "device_id": device["id"],
                "device": f"{device.get('manufacturer')} {device.get('model')}",
                "scenario": "Компрометация видеопотока",
                "indicators": [
                    "Прерывание видеопотока",
                    "Артефакты сжатия, указывающие на вмешательство",
                    "Несанкционированный доступ к видеоархиву"
                ],
                "response_time": "30 минут",
                "escalation_level": "Уровень 2"
            })
            
        elif any(x in device_type for x in ["маршрутизатор", "коммутатор"]):
            scenarios.append({
                "scenario_id": f"INC-{device['id']}-003",
                "device_id": device["id"],
                "device": f"{device.get('manufacturer')} {device.get('model')}",
                "scenario": "Изменение сетевой конфигурации",
                "indicators": [
                    "Изменение таблицы маршрутизации",
                    "Добавление статических маршрутов",
                    "Изменение правил фаервола"
                ],
                "response_time": "10 минут",
                "escalation_level": "Уровень 1"
            })
        
        return scenarios
    
    def _analyze_dynamic_access(self):
        """5.3. Динамически менять уровень доступа устройств по health score"""
        
        # Расчет health score для каждого устройства
        for device in self.devices:
            health_score = self._calculate_health_score(device)
            access_policies = self._generate_dynamic_access_policies(device, health_score)
            
            recommendation = {
                "device_id": device["id"],
                "device": f"{device.get('manufacturer')} {device.get('model')}",
                "type": device.get("type", ""),
                "health_score": health_score,
                "access_tiers": self._define_access_tiers(health_score["score"]),
                "dynamic_policies": access_policies,
                "recalculation_frequency": self._get_score_recalculation_freq(device),
                "remediation_actions": self._get_remediation_actions(health_score["score"])
            }
            
            self.recommendations["dynamic_access"].append(recommendation)
        
        # Общая система health scoring
        scoring_system = {
            "model": "Адаптивная модель оценки доверия",
            "factors": [
                {"factor": "Безопасность устройства", "weight": 0.35},
                {"factor": "Поведенческие аномалии", "weight": 0.25},
                {"factor": "Соответствие политикам", "weight": 0.20},
                {"factor": "Внешние угрозы", "weight": 0.10},
                {"factor": "Историческая надежность", "weight": 0.10}
            ],
            "score_ranges": {
                "0-40": "КРАСНЫЙ (критический риск)",
                "41-70": "ЖЕЛТЫЙ (повышенный риск)", 
                "71-90": "ЗЕЛЕНЫЙ (нормальный риск)",
                "91-100": "СИНИЙ (высокое доверие)"
            },
            "update_mechanism": "Непрерывная оценка с ежечасным пересчетом"
        }
        
        self.recommendations["dynamic_access"].append({
            "type": "Система оценки",
            "scoring_system": scoring_system
        })
    
    def _calculate_health_score(self, device: Dict) -> Dict:
        """Рассчитать health score для устройства"""
        score = 100  # Начальный балл
        
        factors = []
        
        # Фактор 1: Шифрование
        if not device.get("encryption", False):
            score -= 25
            factors.append({"factor": "Отсутствие шифрования", "impact": -25})
        
        # Фактор 2: Критичность
        if device.get("critical", False):
            score -= 5  # Критические устройства изначально имеют меньший довесок
            factors.append({"factor": "Критическое устройство", "impact": -5})
        
        # Фактор 3: Категория КИИ
        kii_cat = device.get("kii_category", 0)
        if kii_cat in [1, 2]:
            score -= 10
            factors.append({"factor": "КИИ 1-2 категории", "impact": -10})
        
        # Фактор 4: Физический доступ
        if device.get("physical_access", False):
            score -= 15
            factors.append({"factor": "Возможность физического доступа", "impact": -15})
        
        # Фактор 5: Импортное оборудование
        domestic_manufacturers = ["Овен", "Элвис-Нео", "Ростелеком", "Болид", "Киберлок"]
        if device.get("manufacturer") not in domestic_manufacturers:
            score -= 10
            factors.append({"factor": "Импортное оборудование", "impact": -10})
        
        # Обеспечиваем, что score не уйдет ниже 0
        score = max(0, min(100, score))
        
        return {
            "score": score,
            "factors": factors,
            "last_calculated": datetime.now().isoformat()
        }
    
    def _define_access_tiers(self, score: int) -> List[Dict]:
        """Определить уровни доступа на основе health score"""
        if score >= 90:
            return [
                {"tier": "ПОЛНЫЙ ДОСТУП", "description": "Все операции разрешены", "color": "синий"},
                {"tier": "ОГРАНИЧЕННЫЙ", "description": "Только чтение данных", "color": "зеленый"},
                {"tier": "МИНИМАЛЬНЫЙ", "description": "Только ping и статус", "color": "желтый"},
                {"tier": "БЛОКИРОВКА", "description": "Полная изоляция", "color": "красный"}
            ]
        elif score >= 70:
            return [
                {"tier": "ОГРАНИЧЕННЫЙ", "description": "Только чтение данных", "color": "зеленый"},
                {"tier": "МИНИМАЛЬНЫЙ", "description": "Только ping и статус", "color": "желтый"},
                {"tier": "БЛОКИРОВКА", "description": "Полная изоляция", "color": "красный"}
            ]
        elif score >= 40:
            return [
                {"tier": "МИНИМАЛЬНЫЙ", "description": "Только ping и статус", "color": "желтый"},
                {"tier": "БЛОКИРОВКА", "description": "Полная изоляция", "color": "красный"}
            ]
        else:
            return [
                {"tier": "БЛОКИРОВКА", "description": "Полная изоляция", "color": "красный"}
            ]
    
    def _generate_dynamic_access_policies(self, device: Dict, health_score: Dict) -> List[Dict]:
        """Сгенерировать динамические политики доступа"""
        policies = []
        score = health_score["score"]
        
        # Базовые политики
        base_policies = [
            {
                "policy_id": f"DYN-{device['id']}-001",
                "condition": f"Health Score >= 90",
                "access_level": "ПОЛНЫЙ ДОСТУП",
                "permissions": ["Чтение/запись", "Управление", "Обновление"],
                "authentication": "MFA раз в 8 часов"
            },
            {
                "policy_id": f"DYN-{device['id']}-002",
                "condition": f"70 <= Health Score < 90", 
                "access_level": "ОГРАНИЧЕННЫЙ",
                "permissions": ["Чтение данных", "Просмотр статуса"],
                "authentication": "MFA при каждом доступе"
            },
            {
                "policy_id": f"DYN-{device['id']}-003",
                "condition": f"40 <= Health Score < 70",
                "access_level": "МИНИМАЛЬНЫЙ",
                "permissions": ["Ping", "Просмотр базового статуса"],
                "authentication": "MFA + дополнительная проверка"
            },
            {
                "policy_id": f"DYN-{device['id']}-004",
                "condition": f"Health Score < 40",
                "access_level": "БЛОКИРОВКА",
                "permissions": ["Нет доступа"],
                "authentication": "Заблокировано"
            }
        ]
        
        policies.extend(base_policies)
        
        # Дополнительные условия
        if device.get("critical", False):
            policies.append({
                "policy_id": f"DYN-{device['id']}-005",
                "condition": "Обнаружена аномальная активность",
                "access_level": "БЛОКИРОВКА",
                "permissions": ["Нет доступа"],
                "authentication": "Заблокировано до расследования",
                "automatic": True
            })
        
        return policies
    
    def _get_score_recalculation_freq(self, device: Dict) -> str:
        """Определить частоту пересчета health score"""
        if device.get("kii_category", 0) in [1, 2] or device.get("critical", False):
            return "Каждые 15 минут"
        elif device.get("data_volume") == "высокая":
            return "Каждый час"
        else:
            return "Каждые 4 часа"
    
    def _get_remediation_actions(self, score: int) -> List[Dict]:
        """Определить действия по восстановлению health score"""
        actions = []
        
        if score < 40:
            actions.extend([
                {"action": "Немедленная изоляция устройства", "priority": "Критический"},
                {"action": "Анализ на наличие компрометации", "priority": "Высокий"},
                {"action": "Обновление прошивки/ПО", "priority": "Высокий"},
                {"action": "Перевыпуск сертификатов/ключей", "priority": "Средний"}
            ])
        elif score < 70:
            actions.extend([
                {"action": "Усиление мониторинга", "priority": "Высокий"},
                {"action": "Проверка конфигурации", "priority": "Средний"},
                {"action": "Обновление антивирусных баз", "priority": "Средний"}
            ])
        
        return actions
    
    def _analyze_firmware_verification(self):
        """5.4. Настроить верификацию встроенного ПО (firmware)"""
        
        for device in self.devices:
            verification_plan = self._generate_firmware_verification_plan(device)
            self.recommendations["firmware_verification"].append(verification_plan)
        
        # Система управления обновлениями
        update_management = {
            "system_architecture": "Централизованный сервер обновлений",
            "components": [
                "Сервер хранения прошивок",
                "Система подписи (УЦ ФСТЭК)",
                "Сервер распределения обновлений",
                "Агенты на устройствах",
                "Система отчетности"
            ],
            "security_measures": [
                "Хранение прошивок в зашифрованном виде",
                "Цифровая подпись ГОСТ Р 34.10-2012",
                "Контроль целостности при передаче",
                "Ведение журнала всех операций"
            ],
            "compliance": ["ФСТЭК №239", "ГОСТ Р 57580.1-2017", "ФЗ-152"]
        }
        
        self.recommendations["firmware_verification"].append({
            "type": "Система управления",
            "update_management": update_management
        })
    
    def _generate_firmware_verification_plan(self, device: Dict) -> Dict:
        """Сгенерировать план верификации прошивки для устройства"""
        
        # Определение текущего состояния прошивки
        current_fw = {
            "version": "Неизвестно",
            "hash": "Не вычислен",
            "signature": "Не проверена",
            "last_update": "Неизвестно"
        }
        
        # План верификации
        verification_steps = []
        
        if device.get("compute_power") in ["средняя", "высокая"]:
            verification_steps.extend([
                "1. Установка агента верификации прошивки",
                "2. Регулярный расчет хэша прошивки (SHA-256/ГОСТ Р 34.11-2012)",
                "3. Проверка цифровой подписи производителя",
                "4. Сравнение с эталоном в базе доверенных прошивок"
            ])
        else:
            verification_steps.extend([
                "1. Периодический опрос версии прошивки",
                "2. Внешняя проверка целостности через сетевой анализ",
                "3. Сравнение с whitelist разрешенных версий",
                "4. Анализ поведения на предмет отклонений"
            ])
        
        # Политика обновлений
        update_policy = {
            "frequency": self._get_update_frequency(device),
            "window": self._get_update_window(device),
            "rollback": "Автоматический откат при неудачном обновлении",
            "testing": "Обязательное тестирование в изолированной среде",
            "approval": "Требуется утверждение ответственным лицом"
        }
        
        return {
            "device_id": device["id"],
            "device": f"{device.get('manufacturer')} {device.get('model')}",
            "current_firmware": current_fw,
            "verification_method": self._get_verification_method(device),
            "verification_steps": verification_steps,
            "update_policy": update_policy,
            "compliance_requirements": self._get_firmware_compliance(device)
        }
    
    def _get_verification_method(self, device: Dict) -> str:
        """Определить метод верификации прошивки"""
        if device.get("kii_category", 0) in [1, 2]:
            return "Аппаратная верификация (TPM/HSM) с использованием ГОСТ"
        elif device.get("compute_power") in ["средняя", "высокая"]:
            return "Программная верификация с цифровой подписью"
        else:
            return "Контрольная сумма и whitelist версий"
    
    def _get_update_frequency(self, device: Dict) -> str:
        """Определить частоту обновлений прошивки"""
        if device.get("kii_category", 0) in [1, 2]:
            return "Критические обновления - немедленно, остальные - ежемесячно"
        elif device.get("critical", False):
            return "Ежеквартально или при обнаружении уязвимостей"
        else:
            return "По мере выхода обновлений, но не реже раза в год"
    
    def _get_update_window(self, device: Dict) -> Dict:
        """Определить окно обновлений"""
        if device.get("critical", False):
            return {"day": "Суббота", "time": "01:00-04:00", "max_duration": "3 часа"}
        else:
            return {"day": "Воскресенье", "time": "03:00-06:00", "max_duration": "3 часа"}
    
    def _get_firmware_compliance(self, device: Dict) -> List[str]:
        """Определить требования соответствия для прошивки"""
        requirements = []
        
        if device.get("kii_category", 0) in [1, 2]:
            requirements.extend([
                "Обязательное использование отечественных криптоалгоритмов",
                "Сертификация ФСТЭК/ФСБ",
                "Ведение полного журнала изменений",
                "Возможность аппаратного отката"
            ])
        
        if any(x in device.get("type", "").lower() for x in ["камера", "датчик"]):
            requirements.append("Проверка на отсутствие backdoor")
        
        return requirements
    
    def _generate_implementation_plan(self):
        """Сгенерировать план внедрения системы мониторинга"""
        
        implementation_phases = [
            {
                "phase": "Фаза 1: Подготовка инфраструктуры (1-2 месяца)",
                "activities": [
                    "Развертывание SIEM системы (MaxPatrol SIEM или аналог)",
                    "Установка систем сбора логов и метрик",
                    "Настройка централизованного хранилища данных",
                    "Разработка политик мониторинга и реагирования"
                ],
                "deliverables": [
                    "Работающая SIEM система",
                    "Реестр источников данных мониторинга",
                    "Утвержденные политики безопасности"
                ]
            },
            {
                "phase": "Фаза 2: Внедрение мониторинга (2-3 месяца)",
                "activities": [
                    "Внедрение агентов мониторинга на критических устройствах",
                    "Настройка корреляционных правил и детектирования аномалий",
                    "Интеграция с системами управления сетью",
                    "Обучение персонала SOC"
                ],
                "deliverables": [
                    "Мониторинг 100% критических устройств",
                    "Настроенные правила корреляции",
                    "Обученная первая линия поддержки"
                ]
            },
            {
                "phase": "Фаза 3: Автоматизация (3-4 месяца)",
                "activities": [
                    "Внедрение SOAR платформы (КиберЛок SOAR или аналог)",
                    "Разработка playbook для автоматического реагирования",
                    "Настройка системы health scoring",
                    "Интеграция с системами инвентаризации"
                ],
                "deliverables": [
                    "Автоматизированные сценарии реагирования",
                    "Система динамического управления доступом",
                    "Интегрированная платформа безопасности"
                ]
            },
            {
                "phase": "Фаза 4: Оптимизация и развитие (постоянно)",
                "activities": [
                    "Внедрение машинного обучения для анализа поведения",
                    "Расширение мониторинга на все устройства",
                    "Регулярные учения и тестирование системы",
                    "Аудит и оптимизация правил мониторинга"
                ],
                "deliverables": [
                    "Система предиктивной аналитики",
                    "Полное покрытие мониторингом",
                    "Регулярные отчеты об эффективности"
                ]
            }
        ]
        
        self.recommendations["implementation_plan"] = implementation_phases
        
        # Требования к интеграции
        integration_reqs = [
            {
                "system": "SIEM платформа",
                "integrations": [
                    {"target": "Сетевые устройства", "protocol": "Syslog, SNMP Trap"},
                    {"target": "Серверы", "protocol": "Windows Event Log, Syslog"},
                    {"target": "Приложения", "protocol": "REST API, файлы логов"}
                ],
                "data_volume": f"~{len(self.devices) * 100} MB/день"
            },
            {
                "system": "SOAR платформа",
                "integrations": [
                    {"target": "SIEM", "protocol": "REST API, CEF"},
                    {"target": "Система управления сетью", "protocol": "SSH, REST API"},
                    {"target": "Сервис уведомлений", "protocol": "Email, Telegram API"}
                ],
                "response_time": "Менее 5 минут для критических инцидентов"
            },
            {
                "system": "База данных CMDB",
                "integrations": [
                    {"target": "Система инвентаризации", "protocol": "REST API, база данных"},
                    {"target": "Система управления активами", "protocol": "CSV импорт, API"}
                ],
                "update_frequency": "Ежедневная синхронизация"
            }
        ]
        
        self.recommendations["integration_requirements"] = integration_reqs
    
    def generate_report(self) -> str:
        """Сгенерировать отчет по этапу 5"""
        report = []
        report.append("="*80)
        report.append("ОТЧЕТ ПО ЭТАПУ 5: СИСТЕМА МОНИТОРИНГА И ПОДДЕРЖКИ")
        report.append("="*80)
        
        # Основная информация
        report.append(f"\nОрганизация: {self.organization}")
        report.append(f"Дата генерации: {datetime.now().strftime('%d.%m.%Y %H:%M')}")
        
        # Статистика
        total = len(self.devices)
        critical = sum(1 for d in self.devices if d.get("critical", False))
        kii = sum(1 for d in self.devices if d.get("kii_category", 0) in [1, 2])
        
        report.append(f"\nСТАТИСТИКА ПО МОНИТОРИНГУ:")
        report.append(f"  Всего устройств: {total}")
        report.append(f"  Критических устройств: {critical}")
        report.append(f"  Устройств КИИ 1-2 категории: {kii}")
        
        # 5.1. Поведенческий анализ
        report.append(f"\n\n5.1. ПОВЕДЕНЧЕСКИЙ АНАЛИЗ")
        report.append("-"*60)
        
        # Группируем по уровню мониторинга
        monitoring_levels = {}
        for rec in self.recommendations["behavioral_analysis"]:
            if isinstance(rec, dict) and "monitoring_level" in rec:
                level = rec["monitoring_level"]
                if level not in monitoring_levels:
                    monitoring_levels[level] = 0
                monitoring_levels[level] += 1
        
        report.append(f"\nРаспределение по уровням мониторинга:")
        for level, count in monitoring_levels.items():
            report.append(f"  • {level}: {count} устройств")
        
        # Примеры правил обнаружения аномалий
        report.append(f"\nПримеры правил обнаружения аномалий:")
        anomaly_rules = []
        for rec in self.recommendations["behavioral_analysis"]:
            if isinstance(rec, dict) and "anomaly_detection_rules" in rec:
                for rule in rec["anomaly_detection_rules"][:1]:  # По одному правилу от устройства
                    if rule not in anomaly_rules:
                        anomaly_rules.append(rule)
        
        for rule in anomaly_rules[:3]:
            report.append(f"  • {rule.get('description')}")
            report.append(f"    Условие: {rule.get('condition')}")
            report.append(f"    Действие: {rule.get('action')}")
        
        # 5.2. Автоматизация ответа на инциденты
        report.append(f"\n\n5.2. АВТОМАТИЗАЦИЯ ОТВЕТА НА ИНЦИДЕНТЫ")
        report.append("-"*60)
        
        incident_response = self.recommendations["incident_response"]
        playbooks = [r["content"] for r in incident_response if isinstance(r, dict) and r.get("type") == "Playbook"]
        
        if playbooks:
            report.append(f"\nКлючевые playbook для автоматизации:")
            for playbook in playbooks[:2]:
                report.append(f"  • {playbook[0].get('name')}")
                report.append(f"    Триггеры: {', '.join(playbook[0].get('triggers', []))}")
        
        # 5.3. Динамическое изменение уровня доступа
        report.append(f"\n\n5.3. ДИНАМИЧЕСКОЕ ИЗМЕНЕНИЕ УРОВНЯ ДОСТУПА")
        report.append("-"*60)
        
        # Распределение health score
        score_ranges = {"0-40": 0, "41-70": 0, "71-90": 0, "91-100": 0}
        for rec in self.recommendations["dynamic_access"]:
            if isinstance(rec, dict) and "health_score" in rec:
                score = rec["health_score"]["score"]
                if score <= 40:
                    score_ranges["0-40"] += 1
                elif score <= 70:
                    score_ranges["41-70"] += 1
                elif score <= 90:
                    score_ranges["71-90"] += 1
                else:
                    score_ranges["91-100"] += 1
        
        report.append(f"\nРаспределение устройств по Health Score:")
        for range_name, count in score_ranges.items():
            if count > 0:
                report.append(f"  • {range_name}: {count} устройств")
        
        # 5.4. Верификация встроенного ПО
        report.append(f"\n\n5.4. ВЕРИФИКАЦИЯ ВСТРОЕННОГО ПО")
        report.append("-"*60)
        
        firmware_verification = [r for r in self.recommendations["firmware_verification"] 
                                if isinstance(r, dict) and "device" in r]
        
        if firmware_verification:
            report.append(f"\nМетоды верификации прошивки:")
            methods = {}
            for ver in firmware_verification:
                method = ver.get("verification_method", "Неизвестно")
                if method not in methods:
                    methods[method] = 0
                methods[method] += 1
            
            for method, count in methods.items():
                report.append(f"  • {method}: {count} устройств")
        
        # План внедрения
        report.append(f"\n\nПЛАН ВНЕДРЕНИЯ СИСТЕМЫ МОНИТОРИНГА")
        report.append("-"*60)
        
        plan = self.recommendations["implementation_plan"]
        if plan:
            report.append(f"\nОбщая продолжительность: 8-10 месяцев")
            for phase in plan[:2]:  # Показываем первые 2 фазы
                report.append(f"\n{phase['phase']}:")
                for activity in phase.get("activities", [])[:2]:
                    report.append(f"  • {activity}")
        
        # Нормативные требования
        report.append(f"\n\nНОРМАТИВНЫЕ ТРЕБОВАНИЯ К МОНИТОРИНГУ")
        report.append("-"*60)
        requirements = [
            "• ФСТЭК Приказ №239: Требования к мониторингу и реагированию на инциденты",
            "• ГОСТ Р 57580.1-2017: Мониторинг систем КИИ",
            "• ФЗ-187: Требования к безопасности критической информационной инфраструктуры",
            "• ISO/IEC 27035: Управление инцидентами информационной безопасности",
            "• NIST SP 800-61: Рекомендации по обработке инцидентов компьютерной безопасности"
        ]
        
        for req in requirements:
            report.append(f"  {req}")
        
        # Ориентировочная стоимость
        report.append(f"\n\nОРИЕНТИРОВОЧНАЯ СТОИМОСТЬ ВНЕДРЕНИЯ")
        report.append("-"*60)
        cost_breakdown = [
            "• SIEM система (MaxPatrol, Аванпост): от 2,000,000 руб.",
            "• SOAR платформа (КиберЛок, PT Security Vision): от 1,500,000 руб.",
            "• Система управления обновлениями: от 500,000 руб.",
            "• Интеграционные работы: от 1,000,000 руб.",
            "• Обучение персонала SOC: от 800,000 руб.",
            f"• ИТОГО для {total} устройств: от 5,800,000 руб."
        ]
        
        for cost in cost_breakdown:
            report.append(f"  {cost}")
        
        return "\n".join(report)
    
    def save_report_to_file(self, filename: str = "monitoring_system_report.txt"):
        """Сохранить отчет в файл"""
        report_text = self.generate_report()
        
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        filepath = reports_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report_text)
        
        print(f"\nОтчет сохранен в файл: {filepath}")
        return str(filepath)
    
    def print_summary(self):
        """Вывести краткое содержание рекомендаций"""
        print("\n" + "="*80)
        print("КРАТКОЕ СОДЕРЖАНИЕ РЕКОМЕНДАЦИЙ ПО МОНИТОРИНГУ (ЭТАП 5)")
        print("="*80)
        
        # Статистика
        total = len(self.devices)
        critical = sum(1 for d in self.devices if d.get("critical", False))
        
        # Расчет среднего health score
        scores = []
        for rec in self.recommendations["dynamic_access"]:
            if isinstance(rec, dict) and "health_score" in rec:
                scores.append(rec["health_score"]["score"])
        
        avg_score = sum(scores) / len(scores) if scores else 0
        
        print(f"\nСТАТИСТИКА:")
        print(f"  Всего устройств: {total}")
        print(f"  Критических устройств: {critical}")
        print(f"  Средний Health Score: {avg_score:.1f}/100")
        
        print(f"\nКЛЮЧЕВЫЕ РЕКОМЕНДАЦИИ:")
        
        print(f"  1. Поведенческий анализ:")
        print(f"     • Внедрить SIEM систему с поддержкой машинного обучения")
        print(f"     • Настроить правила обнаружения аномалий для каждого типа устройств")
        
        print(f"\n  2. Автоматизация инцидентов:")
        print(f"     • Внедрить SOAR платформу для автоматического реагирования")
        print(f"     • Разработать playbook для наиболее критичных сценариев")
        
        print(f"\n  3. Динамический контроль доступа:")
        print(f"     • Внедрить систему health scoring для оценки доверия")
        print(f"     • Настроить автоматическое изменение уровня доступа")
        
        print(f"\n  4. Верификация прошивок:")
        print(f"     • Реализовать централизованную систему управления обновлениями")
        print(f"     • Внедрить проверку цифровой подписи и целостности прошивок")
        
        print(f"\nПРИОРИТЕТЫ ВНЕДРЕНИЯ:")
        priorities = [
            "1. Критические устройства КИИ 1-2 категории (первые 30 дней)",
            "2. Остальные критичные устройства (60 дней)",
            "3. Устройства с высокой нагрузкой данных (90 дней)",
            "4. Все остальные устройства (180 дней)"
        ]
        
        for priority in priorities:
            print(f"  {priority}")
        
        print(f"\nТЕХНОЛОГИЧЕСКИЕ РЕШЕНИЯ:")
        solutions = [
            "• Отечественные: MaxPatrol SIEM, КиберЛок SOAR, КриптоПро CSP",
            "• Зарубежные (при необходимости): Splunk, IBM QRadar, CyberArk",
            "• Системы мониторинга: Zabbix, Nagios, Prometheus с отечественными дополнениями"
        ]
        
        for solution in solutions:
            print(f"  {solution}")
        
        print(f"\n" + "="*80)