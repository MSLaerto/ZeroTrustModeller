"""
Модуль для планирования внедрения многофакторной аутентификации (MFA) (Этап 4)
Реализует логику выбора методов аутентификации на основе предоставленной блок-схемы.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

class MFAPlanner:
    """Планировщик внедрения MFA для Zero Trust IoT"""
    
    def __init__(self, infrastructure: Dict):
        self.infrastructure = infrastructure
        self.devices = infrastructure.get("devices", [])
        self.organization = infrastructure.get("organization", "Неизвестная организация")
        
        # Справочник отечественных решений MFA
        self.domestic_solutions = {
            "hardware_token": [
                {"name": "Рутокен ЭЦП 2.0", "type": "Аппаратный токен", "standard": "ГОСТ Р 34.10-2012"},
                {"name": "JaCarta-2 ГОСТ", "type": "Аппаратный токен", "standard": "ГОСТ Р 34.10-2012"},
                {"name": "eToken ГОСТ", "type": "Аппаратный токен", "standard": "ФСТЭК/ФСБ"}
            ],
            "software_token": [
                {"name": "Яндекс.Ключ", "type": "Мобильное приложение", "standard": "TOTP (отечественный)"},
                {"name": "КриптоПро TSP", "type": "Программный клиент", "standard": "ГОСТ"},
                {"name": "ViPNet TOTP", "type": "Программный клиент", "standard": "ФСТЭК"}
            ],
            "biometric": [
                {"name": "БиоКлюч Ростелеком", "type": "Биометрическая аутентификация", "standard": "ФЗ-152"},
                {"name": "СБИС Биометрия", "type": "Распознавание лица/голоса", "standard": "ГОСТ Р 52633.4"}
            ],
            "push_notification": [
                {"name": "КиберЛок АИС", "type": "Push-уведомления с ИИ", "standard": "Отечественная разработка"},
                {"name": "ГосKey Мобильный", "type": "Push + геолокация", "standard": "ФСТЭК"}
            ]
        }
        
        self.recommendations = {
            "authentication_methods": [],      # 4.1 Методы аутентификации
            "adaptive_access": [],             # 4.2 Адаптивный доступ
            "access_policies": [],             # 4.3 Политики доступа
            "admin_protection": [],            # 4.4 Защита административных интерфейсов
            "integration_requirements": [],    # Требования интеграции
            "implementation_plan": []          # План внедрения
        }
    
    def analyze_infrastructure(self) -> Dict:
        """Проанализировать инфраструктуру и сгенерировать рекомендации по MFA"""
        print("\n" + "="*80)
        print("ЭТАП 4: АНАЛИЗ И ПЛАНИРОВАНИЕ МНОГОФАКТОРНОЙ АУТЕНТИФИКАЦИИ (MFA)")
        print("="*80)
        
        # 4.1. Определение методов аутентификации
        print("\n[4.1] ОПРЕДЕЛЕНИЕ МЕТОДОВ АУТЕНТИФИКАЦИИ")
        print("-"*40)
        self._analyze_authentication_methods()
        
        # 4.2. Адаптивный доступ
        print("\n[4.2] АНАЛИЗ АДАПТИВНОГО ДОСТУПА")
        print("-"*40)
        self._analyze_adaptive_access()
        
        # 4.3. Политики доступа
        print("\n[4.3] АНАЛИЗ ПОЛИТИК ДОСТУПА")
        print("-"*40)
        self._analyze_access_policies()
        
        # 4.4. Защита административных интерфейсов
        print("\n[4.4] АНАЛИЗ ЗАЩИТЫ АДМИНИСТРАТИВНЫХ ИНТЕРФЕЙСОВ")
        print("-"*40)
        self._analyze_admin_protection()
        
        # Генерация плана внедрения
        self._generate_implementation_plan()
        
        return self.recommendations
    
    def _analyze_authentication_methods(self):
        """4.1. Определить методы аутентификации на основе блок-схемы"""
        
        # Анализ всех устройств
        for device in self.devices:
            device_id = device["id"]
            device_type = device.get("type", "")
            manufacturer = device.get("manufacturer", "")
            model = device.get("model", "")
            
            # Определяем тип субъекта доступа
            # Упрощение: если устройство имеет интерфейс управления - предполагаем доступ людей
            has_admin_interface = any(
                proto in device.get("protocols", []) 
                for proto in ["SSH", "HTTPS", "HTTP", "TELNET"]
            )
            
            # Собираем критерии для блок-схемы
            is_human_access = has_admin_interface
            is_kii = device.get("kii_category", 0) in [1, 2, 3]
            has_personal_data = self._device_has_personal_data(device)
            manages_iot = "маршрутизатор" in device_type.lower() or "коммутатор" in device_type.lower()
            
            # Применение логики блок-схемы
            mfa_method = self._select_mfa_method_by_flowchart(
                is_human_access, is_kii, has_personal_data, manages_iot, device
            )
            
            # Формируем рекомендацию для устройства
            recommendation = {
                "device_id": device_id,
                "device": f"{manufacturer} {model}",
                "type": device_type,
                "access_scenario": self._determine_access_scenario(device),
                "selected_method": mfa_method["method"],
                "recommended_solution": mfa_method["solution"],
                "rationale": mfa_method["rationale"],
                "implementation_priority": self._get_mfa_priority(device, mfa_method),
                "configuration_steps": self._generate_mfa_config_steps(device, mfa_method)
            }
            
            self.recommendations["authentication_methods"].append(recommendation)
        
        # Общие рекомендации по методам
        general_methods = [
            {
                "category": "Для критической инфраструктуры (КИИ 1-2 категории)",
                "methods": [
                    "TPM-модули + сертификаты ГОСТ Р 34.10-2012",
                    "Аппаратные токены (Рутокен, JaCarta) + биометрия",
                    "Двухканальная аутентификация с разделением ролей"
                ],
                "standard": "Требования ФСТЭК №239, ГОСТ Р 57580.1-2017"
            },
            {
                "category": "Для устройств с персональными данными",
                "methods": [
                    "Сертификаты ГОСТ + TLS с mutual authentication",
                    "Динамические одноразовые пароли (TOTP) через отечественные шлюзы"
                ],
                "standard": "ФЗ-152 «О персональных данных», Приказ ФСТЭК №21"
            },
            {
                "category": "Для пользовательского доступа к IoT устройствам",
                "methods": [
                    "Push-уведомления с поведенческим ИИ (анализ геолокации, времени)",
                    "Отечественные TOTP (Яндекс.Ключ, КриптоПро TOTP)"
                ],
                "standard": "Рекомендации ФСТЭК, лучшие практики"
            }
        ]
        
        for method_group in general_methods:
            self.recommendations["authentication_methods"].append({
                "type": "Общая рекомендация",
                "category": method_group["category"],
                "methods": method_group["methods"],
                "regulatory_standard": method_group["standard"]
            })
    
    def _select_mfa_method_by_flowchart(self, is_human: bool, is_kii: bool, 
                                       has_personal_data: bool, manages_iot: bool,
                                       device: Dict) -> Dict:
        """Выбрать метод MFA по логике блок-схемы"""
        
        if not is_human:
            # Субъект - устройство
            if is_kii:
                return {
                    "method": "Устройство-устройство аутентификация с TPM",
                    "solution": self.domestic_solutions["hardware_token"][0],
                    "rationale": "Устройство КИИ требует аппаратного модуля доверенной среды (TPM) для взаимной аутентификации"
                }
            elif has_personal_data:
                return {
                    "method": "Сертификатная аутентификация с TLS",
                    "solution": {"name": "Сертификаты УЦ ФСТЭК", "type": "PKI", "standard": "ГОСТ Р 34.10-2012"},
                    "rationale": "Передача персональных данных требует сертифицированного шифрования и аутентификации"
                }
            else:
                return {
                    "method": "Отечественные TOTP через шлюз",
                    "solution": self.domestic_solutions["software_token"][1],
                    "rationale": "Для неперсональных данных достаточно защищенного TOTP через отечественный криптошлюз"
                }
        else:
            # Субъект - человек
            if is_kii:
                if manages_iot:
                    return {
                        "method": "Аппаратный токен + биометрия",
                        "solution": {
                            "name": f"{self.domestic_solutions['hardware_token'][0]['name']} + {self.domestic_solutions['biometric'][0]['name']}",
                            "type": "Комбинированная аутентификация",
                            "standard": "ФСТЭК, ГОСТ Р ИСО/МЭК 19792"
                        },
                        "rationale": "Административный доступ к КИИ требует максимального уровня доверия с двумя независимыми факторами"
                    }
                else:
                    return {
                        "method": "Аппаратный токен + сертификат",
                        "solution": self.domestic_solutions["hardware_token"][1],
                        "rationale": "Доступ пользователя к КИИ требует аппаратного токена с сертификатом"
                    }
            else:
                if manages_iot:
                    return {
                        "method": "Push-уведомления с ИИ анализом",
                        "solution": self.domestic_solutions["push_notification"][0],
                        "rationale": "Управление IoT устройствами требует удобства и безопасности с анализом контекста доступа"
                    }
                else:
                    return {
                        "method": "Отечественные TOTP",
                        "solution": self.domestic_solutions["software_token"][0],
                        "rationale": "Пользовательский доступ к некритичным системам через отечественное TOTP решение"
                    }
    
    def _device_has_personal_data(self, device: Dict) -> bool:
        """Определяет, обрабатывает ли устройство персональные данные"""
        device_type = device.get("type", "").lower()
        category = device.get("category", "").lower()
        
        # Эвристика: какие устройства обычно работают с персональными данными
        personal_data_indicators = [
            "камера", "видео", "регистратор",  # Видеонаблюдение
            "контроллер доступа", "скуд",       # Системы контроля доступа
            "терминал", "банкомат", "pos",      # Платежные системы
            "медицинск", "диагностическ"        # Медицинское оборудование
        ]
        
        for indicator in personal_data_indicators:
            if indicator in device_type or indicator in category:
                return True
        
        # Проверка по протоколам
        protocols = device.get("protocols", [])
        if any(proto in ["HTTPS", "MQTTS", "RTSPS"] for proto in protocols):
            # Использует шифрование, возможно для защиты ПДн
            return device.get("encryption", False)
        
        return False
    
    def _determine_access_scenario(self, device: Dict) -> str:
        """Определить сценарий доступа к устройству"""
        device_type = device.get("type", "").lower()
        
        if any(x in device_type for x in ["маршрутизатор", "коммутатор", "фаервол"]):
            return "Административный доступ к сетевому оборудованию"
        elif "камера" in device_type or "регистратор" in device_type:
            return "Доступ к системам видеонаблюдения"
        elif "датчик" in device_type:
            return "Доступ к данным датчиков"
        elif "сервер" in device_type:
            return "Доступ к серверам и приложениям"
        elif "пк" in device_type or "ноутбук" in device_type:
            return "Доступ рабочих станций"
        else:
            return "Доступ к IoT устройству"
    
    def _get_mfa_priority(self, device: Dict, mfa_method: Dict) -> str:
        """Определить приоритет внедрения MFA"""
        if device.get("kii_category", 0) in [1, 2]:
            return "КРИТИЧЕСКИЙ (не более 30 дней)"
        elif device.get("critical", False):
            return "ВЫСОКИЙ (не более 60 дней)"
        elif "аппаратный токен" in mfa_method["method"]:
            return "ВЫСОКИЙ (не более 90 дней)"
        else:
            return "СРЕДНИЙ (не более 180 дней)"
    
    def _generate_mfa_config_steps(self, device: Dict, mfa_method: Dict) -> List[str]:
        """Сгенерировать шаги настройки MFA для устройства"""
        steps = []
        device_type = device.get("type", "").lower()
        method = mfa_method["method"]
        
        if "TPM" in method:
            steps.extend([
                "1. Проверить наличие TPM 2.0 модуля на устройстве",
                "2. Активировать TPM в BIOS/UEFI с настройкой отечественных алгоритмов",
                "3. Установить драйверы TPM с поддержкой ГОСТ",
                "4. Сгенерировать ключи ГОСТ Р 34.10-2012 в TPM",
                "5. Настроить политику аутентификации на сервере УЦ ФСТЭК"
            ])
        elif "аппаратный токен" in method:
            steps.extend([
                "1. Приобрести аппаратные токены Рутокен или JaCarta ГОСТ",
                "2. Инициализировать токены через систему управления Рутокен ЦП",
                "3. Записать сертификаты УЦ ФСТЭК на токены",
                "4. Настроить RADIUS сервер (FreeRADIUS с модулем rlm_rutoken)",
                "5. Интегрировать с системой контроля доступа"
            ])
        elif "сертификат" in method:
            steps.extend([
                "1. Настроить УЦ ФСТЭК для выпуска сертификатов устройств",
                "2. Сгенерировать запросы на сертификаты (CSR) для каждого устройства",
                "3. Выпустить сертификаты ГОСТ Р 34.10-2012",
                "4. Настроить mutual TLS аутентификацию на серверах",
                "5. Реализовать механизм отзыва сертификатов (CRL/OCSP)"
            ])
        elif "TOTP" in method:
            steps.extend([
                "1. Установить отечественный TOTP сервер (Яндекс.Ключ Server)",
                "2. Сгенерировать seed-ключи для каждого устройства",
                "3. Настроить синхронизацию времени через NTP с российскими серверами",
                "4. Реализовать API для проверки OTP кодов",
                "5. Настроить резервные механизмы аутентификации"
            ])
        elif "push" in method.lower():
            steps.extend([
                "1. Развернуть сервер КиберЛок АИС или аналог",
                "2. Настроить интеграцию с SIEM системой для контекстного анализа",
                "3. Реализовать мобильное приложение для администраторов",
                "4. Настроить правила анализа рисков (геолокация, время, поведение)",
                "5. Внедрить механизм emergency access"
            ])
        
        # Добавляем общие шаги
        steps.extend([
            "6. Протестировать аутентификацию в изолированном контуре",
            "7. Настроить логирование всех попыток аутентификации",
            "8. Интегрировать с SIEM системой для мониторинга",
            "9. Обучить персонал работе с новой системой аутентификации",
            "10. Составить регламент восстановления доступа при потере токена"
        ])
        
        return steps
    
    def _analyze_adaptive_access(self):
        """4.2. Внедрить адаптивный доступ – динамически ужесточать проверки"""
        
        adaptive_rules = []
        
        # Правила для разных типов устройств
        device_categories = {
            "КИИ устройства": [d for d in self.devices if d.get("kii_category", 0) in [1, 2]],
            "Критические устройства": [d for d in self.devices if d.get("critical", False)],
            "Устройства с физическим доступом": [d for d in self.devices if d.get("physical_access", False)],
            "Пользовательские устройства": [d for d in self.devices if not d.get("critical", False)]
        }
        
        for category, devices in device_categories.items():
            if not devices:
                continue
                
            rules = self._generate_adaptive_rules_for_category(category, devices)
            adaptive_rules.extend(rules)
        
        # Общие правила адаптивного доступа
        general_adaptive_rules = [
            {
                "rule_name": "Контекстная аутентификация по времени",
                "condition": "Попытка доступа вне рабочего времени (19:00-07:00)",
                "action": "Требовать дополнительную аутентификацию (биометрия или звонок подтверждение)",
                "implementation": "Интеграция с Active Directory и системой контроля рабочего времени"
            },
            {
                "rule_name": "Геолокационный контроль",
                "condition": "Попытка доступа из новой/необычной страны/региона",
                "action": "Блокировка доступа с уведомлением SOC и запрос дополнительной верификации",
                "implementation": "Использование IP geolocation баз (MaxMind, отечественные аналоги) + VPN детекция"
            },
            {
                "rule_name": "Аномальное поведение устройства",
                "condition": "Устройство передает аномально большой объем данных или подозрительные запросы",
                "action": "Понижение уровня доверия, требование повторной аутентификации, изоляция сегмента",
                "implementation": "Интеграция с NTA (Network Traffic Analysis) системами (Darktrace, Vectra)"
            },
            {
                "rule_name": "Риск компрометации учетных данных",
                "condition": "Обнаружены учетные данные в базах утекших паролей",
                "action": "Принудительная смена пароля + требование MFA для следующих 10 входов",
                "implementation": "Интеграция с Have I Been Pwned API или отечественными аналогами"
            }
        ]
        
        for rule in general_adaptive_rules:
            adaptive_rules.append(rule)
        
        self.recommendations["adaptive_access"] = adaptive_rules
    
    def _generate_adaptive_rules_for_category(self, category: str, devices: List[Dict]) -> List[Dict]:
        """Сгенерировать адаптивные правила для категории устройств"""
        rules = []
        
        if category == "КИИ устройства":
            rules.extend([
                {
                    "rule_name": "КИИ: Доступ с недоверенных сетей",
                    "condition": "Попытка доступа к КИИ устройству не из доверенного сегмента управления",
                    "action": "Полная блокировка доступа, немедленное оповещение SOC и ФСБ",
                    "implementation": "Настройка на межсетевых экранах и контроллерах доступа",
                    "compliance": "Требование ФСТЭК №239, ФЗ-187"
                },
                {
                    "rule_name": "КИИ: Многократные неудачные попытки",
                    "condition": "Более 3 неудачных попыток аутентификации за 5 минут",
                    "action": "Блокировка IP адреса на 24 часа, извещение службы безопасности",
                    "implementation": "Настройка в WAF, системах предотвращения вторжений"
                }
            ])
        
        elif category == "Устройства с физическим доступом":
            rules.extend([
                {
                    "rule_name": "Физический доступ: Новое устройство в сети",
                    "condition": "Неизвестное устройство подключается к порту с физическим доступом",
                    "action": "Помещение в карантинную VLAN, требование аутентификации администратора",
                    "implementation": "Настройка 802.1X, портовой безопасности на коммутаторах"
                },
                {
                    "rule_name": "Физический доступ: Неавторизованные протоколы",
                    "condition": "Устройство пытается использовать неразрешенные протоколы (Telnet, HTTP)",
                    "action": "Блокировка трафика, переключение на защищенные протоколы (SSH, HTTPS)",
                    "implementation": "Настройка политик на коммутаторах и фаерволе"
                }
            ])
        
        return rules
    
    def _analyze_access_policies(self):
        """4.3. Настроить политики доступа в зависимости от уровня риска"""
        
        # Анализ рисков для каждого устройства
        for device in self.devices:
            risk_level = self._calculate_device_risk_level(device)
            policies = self._generate_access_policies(device, risk_level)
            
            policy_entry = {
                "device_id": device["id"],
                "device": f"{device.get('manufacturer')} {device.get('model')}",
                "risk_level": risk_level["level"],
                "risk_score": risk_level["score"],
                "policies": policies,
                "review_frequency": risk_level["review_frequency"]
            }
            
            self.recommendations["access_policies"].append(policy_entry)
        
        # Рекомендации по управлению политиками
        policy_management = [
            {
                "aspect": "Жизненный цикл политик",
                "recommendations": [
                    "Ежеквартальный пересмотр политик доступа для критических устройств",
                    "Полугодовой пересмотр для устройств среднего риска",
                    "Ежегодный пересмотр для устройств низкого риска",
                    "Автоматический пересмотр при изменении классификации устройства"
                ]
            },
            {
                "aspect": "Сегрегация обязанностей",
                "recommendations": [
                    "Разделение ролей: администратор политик ≠ администратор устройств",
                    "Обязательное согласование изменений политик через систему тикетов",
                    "Ведение аудит-лога всех изменений политик с электронной подписью"
                ]
            },
            {
                "aspect": "Аварийный доступ",
                "recommendations": [
                    "Создание break-glass учетных записей с аппаратным хранением паролей",
                    "Многоуровневое подтверждение для использования аварийного доступа",
                    "Обязательный пост-фактум аудит использования аварийного доступа"
                ]
            }
        ]
        
        for item in policy_management:
            self.recommendations["access_policies"].append({
                "type": "Управление политиками",
                "aspect": item["aspect"],
                "recommendations": item["recommendations"]
            })
    
    def _calculate_device_risk_level(self, device: Dict) -> Dict:
        """Рассчитать уровень риска для устройства"""
        score = 0
        
        # Критерии оценки риска
        if device.get("kii_category", 0) in [1, 2]:
            score += 40
        elif device.get("kii_category", 0) in [3, 4]:
            score += 25
        
        if device.get("critical", False):
            score += 30
        
        if device.get("physical_access", False):
            score += 20
        
        if not device.get("encryption", False):
            score += 15
        
        if device.get("data_volume") == "высокая":
            score += 10
        
        # Определение уровня риска
        if score >= 70:
            level = "КРИТИЧЕСКИЙ"
            review = "Ежемесячно"
        elif score >= 45:
            level = "ВЫСОКИЙ"
            review = "Ежеквартально"
        elif score >= 25:
            level = "СРЕДНИЙ"
            review = "Раз в полгода"
        else:
            level = "НИЗКИЙ"
            review = "Ежегодно"
        
        return {"level": level, "score": score, "review_frequency": review}
    
    def _generate_access_policies(self, device: Dict, risk_level: Dict) -> List[Dict]:
        """Сгенерировать политики доступа для устройства"""
        policies = []
        device_type = device.get("type", "").lower()
        
        # Базовые политики для всех устройств
        base_policies = [
            {
                "policy_type": "Аутентификация",
                "requirement": "Обязательное использование MFA для всех административных доступов",
                "enforcement": "Средствами сетевого оборудования и систем управления доступом"
            },
            {
                "policy_type": "Сессия",
                "requirement": f"Максимальное время сессии: {self._get_session_timeout(risk_level['level'])}",
                "enforcement": "Настройка timeout на устройствах и системах аутентификации"
            },
            {
                "policy_type": "Журналирование",
                "requirement": "Логирование всех успешных и неуспешных попыток доступа",
                "enforcement": "Отправка логов в централизованную SIEM систему"
            }
        ]
        
        policies.extend(base_policies)
        
        # Специфические политики по типу устройства
        if "камера" in device_type or "видео" in device_type:
            policies.append({
                "policy_type": "Доступ к данным",
                "requirement": "Разделение доступа: операторы - просмотр, администраторы - настройки",
                "enforcement": "Настройка RBAC на видеосерверах и NVR"
            })
        
        if any(x in device_type for x in ["маршрутизатор", "коммутатор", "фаервол"]):
            policies.extend([
                {
                    "policy_type": "Изменение конфигурации",
                    "requirement": "Двухэтапное подтверждение для изменений конфигурации",
                    "enforcement": "Интеграция системы управления сценариями с MFA"
                },
                {
                    "policy_type": "Резервное копирование",
                    "requirement": "Автоматическое резервное копирование конфигурации после изменений",
                    "enforcement": "Настройка RANCID, Oxidized или аналогов"
                }
            ])
        
        if device.get("kii_category", 0) in [1, 2]:
            policies.append({
                "policy_type": "КИИ специальные требования",
                "requirement": "Обязательное присутствие двух администраторов для критических изменений",
                "enforcement": "Система управления привилегированным доступом (PAM) с four-eyes principle"
            })
        
        return policies
    
    def _get_session_timeout(self, risk_level: str) -> str:
        """Определить timeout сессии по уровню риска"""
        timeouts = {
            "КРИТИЧЕСКИЙ": "15 минут",
            "ВЫСОКИЙ": "30 минут",
            "СРЕДНИЙ": "2 часа",
            "НИЗКИЙ": "8 часов"
        }
        return timeouts.get(risk_level, "4 часа")
    
    def _analyze_admin_protection(self):
        """4.4. Внедрить усиленную защиту административных интерфейсов"""
        
        admin_interfaces = []
        
        # Идентификация административных интерфейсов
        for device in self.devices:
            admin_protocols = []
            for protocol in device.get("protocols", []):
                if protocol in ["SSH", "HTTPS", "HTTP", "TELNET", "SNMP"]:
                    admin_protocols.append(protocol)
            
            if admin_protocols:
                protection = self._generate_admin_protection_plan(device, admin_protocols)
                admin_interfaces.append(protection)
        
        self.recommendations["admin_protection"] = admin_interfaces
        
        # Системы защиты административных интерфейсов
        protection_systems = [
            {
                "system_type": "Привилегированный доступ (PAM)",
                "solutions": [
                    {"name": "CyberArk", "purpose": "Управление и мониторинг привилегированных учетных записей"},
                    {"name": "Thycotic Secret Server", "purpose": "Безопасное хранение и выдача паролей"},
                    {"name": "Bastion SSH", "purpose": "Шлюз для доступа к SSH интерфейсам"}
                ],
                "implementation": "Внедрение в течение 3-6 месяцев с поэтапной интеграцией"
            },
            {
                "system_type": "Сессионная запись",
                "solutions": [
                    {"name": "Ekran System", "purpose": "Запись и анализ сессий администраторов"},
                    {"name": "Forcepoint DLP", "purpose": "Контроль действий администраторов с критическими данными"}
                ],
                "implementation": "Развертывание на всех критических системах в первую очередь"
            },
            {
                "system_type": "Анализ поведения (UEBA)",
                "solutions": [
                    {"name": "Exabeam", "purpose": "Обнаружение аномального поведения администраторов"},
                    {"name": "Splunk UBA", "purpose": "Машинное обучение для выявления инсайдерских угроз"}
                ],
                "implementation": "Интеграция с SIEM и системами аутентификации"
            }
        ]
        
        for system in protection_systems:
            self.recommendations["admin_protection"].append({
                "type": "Система защиты",
                "system_type": system["system_type"],
                "solutions": system["solutions"],
                "implementation_timeline": system["implementation"]
            })
    
    def _generate_admin_protection_plan(self, device: Dict, admin_protocols: List[str]) -> Dict:
        """Сгенерировать план защиты административных интерфейсов устройства"""
        
        # Базовые меры защиты
        protection_measures = []
        
        # Для каждого протокола - свои меры
        protocol_measures = {
            "SSH": [
                "Отключение аутентификации по паролю, использование только ключей",
                "Настройка двухфакторной аутентификации через PAM",
                "Ограничение алгоритмов шифрования только надежными (chacha20-poly1305@openssh.com)",
                "Использование бастион-хостов для доступа"
            ],
            "HTTPS": [
                "Обязательное использование TLS 1.3 или 1.2 с современными шифрами",
                "Внедрение клиентских сертификатов для административного доступа",
                "Настройка HSTS (HTTP Strict Transport Security)",
                "Регулярное обновление веб-сервера и отключение неиспользуемых модулей"
            ],
            "SNMP": [
                "Использование только SNMPv3 с шифрованием",
                "Ограничение доступа по IP адресам",
                "Регулярная смена community strings",
                "Отключение SNMP на интерфейсах, обращенных в интернет"
            ]
        }
        
        for protocol in admin_protocols:
            if protocol in protocol_measures:
                protection_measures.extend([f"{protocol}: {measure}" for measure in protocol_measures[protocol]])
        
        # Дополнительные меры
        additional_measures = [
            "Изоляция административных интерфейсов в отдельном VLAN",
            "Настройка контроля доступа на межсетевом экране (только с доверенных подсетей)",
            "Внедрение системы одноразовых паролей для доступа к консоли",
            "Регулярный аудит открытых административных портов"
        ]
        
        protection_measures.extend(additional_measures)
        
        # План реагирования на инциденты
        incident_response = [
            "Немедленная блокировка учетной записи при подозрительной активности",
            "Автоматическое оповещение SOC через syslog/SNMP trap",
            "Сбор и сохранение доказательств для последующего расследования",
            "Временная изоляция устройства при подтверждении компрометации"
        ]
        
        return {
            "device_id": device["id"],
            "device": f"{device.get('manufacturer')} {device.get('model')}",
            "admin_protocols": admin_protocols,
            "protection_measures": protection_measures,
            "incident_response": incident_response,
            "monitoring_requirements": [
                "Непрерывный мониторинг попыток доступа",
                "Анализ количества неудачных попыток входа",
                "Мониторинг изменений конфигурации",
                "Контроль времени активности администраторов"
            ]
        }
    
    def _generate_implementation_plan(self):
        """Сгенерировать план внедрения MFA"""
        
        implementation_phases = [
            {
                "phase": "Фаза 1: Подготовка (1-2 месяца)",
                "activities": [
                    "Инвентаризация всех административных доступов и учетных записей",
                    "Выбор и закупка решений MFA (приоритет отечественным разработкам)",
                    "Разработка политик и регламентов использования MFA",
                    "Обучение администраторов и пользователей"
                ],
                "deliverables": [
                    "Реестр учетных записей с уровнями привилегий",
                    "Утвержденные политики безопасности",
                    "Закупленное оборудование и ПО"
                ]
            },
            {
                "phase": "Фаза 2: Пилотное внедрение (2-3 месяца)",
                "activities": [
                    "Внедрение MFA на критических устройствах КИИ",
                    "Настройка систем PAM для административного доступа",
                    "Тестирование отказоустойчивости и восстановления",
                    "Корректировка процессов на основе пилотной эксплуатации"
                ],
                "deliverables": [
                    "Работающая MFA на 20% наиболее критичных устройств",
                    "Документированные процедуры восстановления доступа",
                    "Отчет об эффективности и обнаруженных проблемах"
                ]
            },
            {
                "phase": "Фаза 3: Полное развертывание (4-6 месяцев)",
                "activities": [
                    "Поэтапное внедрение MFA на всех устройствах",
                    "Интеграция с существующей инфраструктурой (AD, SIEM, мониторинг)",
                    "Настройка адаптивного доступа и политик риска",
                    "Проведение тренировок по реагированию на инциденты"
                ],
                "deliverables": [
                    "Полностью функционирующая система MFA на всей инфраструктуре",
                    "Интегрированная система мониторинга и оповещений",
                    "Обученный персонал и утвержденные регламенты"
                ]
            },
            {
                "phase": "Фаза 4: Эксплуатация и оптимизация (постоянно)",
                "activities": [
                    "Регулярный пересмотр политик и правил доступа",
                    "Мониторинг эффективности и обнаружение аномалий",
                    "Обновление и модернизация системы MFA",
                    "Периодические аудиты и тесты на проникновение"
                ],
                "deliverables": [
                    "Ежеквартальные отчеты об эффективности MFA",
                    "Рекомендации по улучшению на основе анализа инцидентов",
                    "Актуализированные политики безопасности"
                ]
            }
        ]
        
        self.recommendations["implementation_plan"] = implementation_phases
        
        # Требования интеграции
        integration_reqs = [
            {
                "system": "Active Directory / LDAP",
                "purpose": "Централизованное управление учетными записями",
                "integration_points": ["Аутентификация пользователей", "Групповые политики", "Блокировка учетных записей"]
            },
            {
                "system": "SIEM (MaxPatrol, Splunk, etc.)",
                "purpose": "Централизованный сбор и анализ логов",
                "integration_points": ["Логи аутентификации", "События безопасности", "Оповещения о подозрительной активности"]
            },
            {
                "system": "Система тикетов (ServiceNow, Jira)",
                "purpose": "Управление запросами на доступ",
                "integration_points": ["Автоматическое создание тикетов", "Согласование доступа", "Журнал изменений"]
            },
            {
                "system": "Сетевые устройства",
                "purpose": "Контроль доступа на уровне сети",
                "integration_points": ["RADIUS аутентификация", "Политики доступа", "Изоляция устройств"]
            }
        ]
        
        self.recommendations["integration_requirements"] = integration_reqs
    
    def generate_report(self) -> str:
        """Сгенерировать отчет по этапу 4"""
        report = []
        report.append("="*80)
        report.append("ОТЧЕТ ПО ЭТАПУ 4: ВНЕДРЕНИЕ МНОГОФАКТОРНОЙ АУТЕНТИФИКАЦИИ (MFA)")
        report.append("="*80)
        
        # Основная информация
        report.append(f"\nОрганизация: {self.organization}")
        report.append(f"Дата генерации: {datetime.now().strftime('%d.%m.%Y %H:%M')}")
        
        # Статистика
        total = len(self.devices)
        requires_mfa = sum(1 for d in self.devices if self._device_requires_mfa(d))
        critical_mfa = sum(1 for d in self.devices if d.get("kii_category", 0) in [1, 2])
        
        report.append(f"\nСТАТИСТИКА ПО MFA:")
        report.append(f"  Всего устройств: {total}")
        report.append(f"  Требуют MFA: {requires_mfa} ({requires_mfa/total*100:.1f}%)")
        report.append(f"  Критически важных устройств (КИИ): {critical_mfa}")
        
        # 4.1. Методы аутентификации
        report.append(f"\n\n4.1. ОПРЕДЕЛЕНИЕ МЕТОДОВ АУТЕНТИФИКАЦИИ")
        report.append("-"*60)
        
        # Группируем методы по типам устройств
        methods_by_type = {}
        for rec in self.recommendations["authentication_methods"]:
            if isinstance(rec, dict) and "device" in rec:
                device_type = rec.get("type", "Другое")
                if device_type not in methods_by_type:
                    methods_by_type[device_type] = []
                methods_by_type[device_type].append(rec)
        
        for device_type, devices in list(methods_by_type.items())[:3]:  # Показываем первые 3 типа
            report.append(f"\n{device_type.upper()}:")
            for device_rec in devices[:2]:  # Показываем первые 2 устройства каждого типа
                report.append(f"  • {device_rec['device']}")
                report.append(f"    Метод: {device_rec['selected_method']}")
                report.append(f"    Приоритет: {device_rec['implementation_priority']}")
        
        # 4.2. Адаптивный доступ
        report.append(f"\n\n4.2. АДАПТИВНЫЙ ДОСТУП")
        report.append("-"*60)
        
        adaptive_rules = self.recommendations["adaptive_access"]
        if adaptive_rules:
            report.append(f"\nКлючевые правила адаптивного доступа:")
            for rule in adaptive_rules[:3]:  # Показываем первые 3 правила
                if isinstance(rule, dict):
                    report.append(f"  • {rule.get('rule_name', 'Правило')}")
                    report.append(f"    Условие: {rule.get('condition', 'не указано')}")
                    report.append(f"    Действие: {rule.get('action', 'не указано')}")
        
        # 4.3. Политики доступа
        report.append(f"\n\n4.3. ПОЛИТИКИ ДОСТУПА")
        report.append("-"*60)
        
        high_risk_policies = [p for p in self.recommendations["access_policies"] 
                             if isinstance(p, dict) and p.get("risk_level") in ["КРИТИЧЕСКИЙ", "ВЫСОКИЙ"]]
        
        if high_risk_policies:
            report.append(f"\nПолитики для устройств высокого риска:")
            for policy in high_risk_policies[:2]:
                report.append(f"  • {policy['device']} (риск: {policy['risk_level']})")
                if policy.get("policies"):
                    for pol in policy["policies"][:2]:
                        report.append(f"    - {pol.get('policy_type')}: {pol.get('requirement')}")
        
        # 4.4. Защита административных интерфейсов
        report.append(f"\n\n4.4. ЗАЩИТА АДМИНИСТРАТИВНЫХ ИНТЕРФЕЙСОВ")
        report.append("-"*60)
        
        admin_protection = [p for p in self.recommendations["admin_protection"] 
                           if isinstance(p, dict) and "device" in p]
        
        if admin_protection:
            report.append(f"\nУстройства с административными интерфейсами: {len(admin_protection)}")
            for protection in admin_protection[:2]:
                report.append(f"  • {protection['device']}")
                report.append(f"    Протоколы: {', '.join(protection.get('admin_protocols', []))}")
        
        # План внедрения
        report.append(f"\n\nПЛАН ВНЕДРЕНИЯ MFA")
        report.append("-"*60)
        
        plan = self.recommendations["implementation_plan"]
        if plan:
            for phase in plan[:2]:  # Показываем первые 2 фазы
                report.append(f"\n{phase['phase']}:")
                for activity in phase.get("activities", [])[:2]:
                    report.append(f"  • {activity}")
        
        # Нормативные требования
        report.append(f"\n\nНОРМАТИВНЫЕ ТРЕБОВАНИЯ К MFA")
        report.append("-"*60)
        requirements = [
            "• ФСТЭК Приказ №239: Обязательная MFA для доступа к КИИ",
            "• ГОСТ Р 57580.1-2017: Требования к аутентификации в системах КИИ",
            "• ФЗ-152: Защита персональных данных при аутентификации",
            "• Приказ ФСТЭК №21: Многофакторная аутентификация в ГИС",
            "• PCI DSS v4.0: Requirement 8.4 - MFA для всего удаленного доступа"
        ]
        
        for req in requirements:
            report.append(f"  {req}")
        
        # Ориентировочная стоимость
        report.append(f"\n\nОРИЕНТИРОВОЧНАЯ СТОИМОСТЬ ВНЕДРЕНИЯ")
        report.append("-"*60)
        cost_breakdown = [
            "• Аппаратные токены (Рутокен/JaCarta): от 3,000 руб./шт.",
            "• Программное обеспечение MFA: от 500,000 руб.",
            "• Система PAM (CyberArk/Thycotic): от 1,500,000 руб.",
            "• Услуги внедрения и интеграции: от 1,000,000 руб.",
            "• Обучение персонала: от 300,000 руб.",
            f"• ИТОГО для {requires_mfa} устройств: от 3,000,000 руб."
        ]
        
        for cost in cost_breakdown:
            report.append(f"  {cost}")
        
        return "\n".join(report)
    
    def _device_requires_mfa(self, device: Dict) -> bool:
        """Определить, требуется ли устройству MFA"""
        return (device.get("kii_category", 0) > 0 or 
                device.get("critical", False) or
                self._device_has_personal_data(device) or
                any(proto in device.get("protocols", []) 
                    for proto in ["SSH", "HTTPS"]))
    
    def save_report_to_file(self, filename: str = "mfa_implementation_report.txt"):
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
        print("КРАТКОЕ СОДЕРЖАНИЕ РЕКОМЕНДАЦИЙ ПО MFA (ЭТАП 4)")
        print("="*80)
        
        # Статистика
        total = len(self.devices)
        requires_mfa = sum(1 for d in self.devices if self._device_requires_mfa(d))
        critical_devices = [d for d in self.devices if d.get("kii_category", 0) in [1, 2]]
        
        print(f"\nСТАТИСТИКА:")
        print(f"  Всего устройств: {total}")
        print(f"  Требуют MFA: {requires_mfa} ({requires_mfa/total*100:.1f}%)")
        print(f"  Критических устройств (КИИ 1-2): {len(critical_devices)}")
        
        print(f"\nКЛЮЧЕВЫЕ РЕКОМЕНДАЦИИ:")
        
        # Рекомендации для критических устройств
        if critical_devices:
            print(f"  1. Для устройств КИИ 1-2 категории:")
            print(f"     • Обязательная аппаратная MFA (Рутокен/JaCarta ГОСТ)")
            print(f"     • Биометрическая аутентификация для администраторов")
            print(f"     • Протоколирование всех действий с отправкой в SIEM")
        
        # Рекомендации по адаптивному доступу
        print(f"\n  2. Адаптивный доступ:")
        print(f"     • Геолокационный контроль доступа")
        print(f"     • Анализ поведения пользователей и устройств")
        print(f"     • Динамическое изменение уровня доверия")
        
        # Приоритеты внедрения
        print(f"\n  3. ПРИОРИТЕТЫ ВНЕДРЕНИЯ:")
        priorities = [
            "1. Устройства КИИ 1-2 категории (первые 30 дней)",
            "2. Критические устройства с физическим доступом (60 дней)",
            "3. Устройства с персональными данными (90 дней)",
            "4. Остальные устройства (180 дней)"
        ]
        
        for priority in priorities:
            print(f"     {priority}")
        
        print(f"\nТЕХНОЛОГИЧЕСКИЕ РЕШЕНИЯ:")
        solutions = [
            "• Отечественные: Яндекс.Ключ, Рутокен, КриптоПро CSP",
            "• Зарубежные (при необходимости): Duo Security, Okta, Microsoft Authenticator",
            "• Системы PAM: CyberArk, Thycotic для привилегированного доступа"
        ]
        
        for solution in solutions:
            print(f"  {solution}")
        
        print(f"\n" + "="*80)