"""
Модуль для планирования сегментации сети (Этап 3)
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from modules.network_model import NetworkAnalyzer, SecurityLevel, NetworkSegment


class SegmentationPlanner:
    """Планировщик сегментации сети для Zero Trust"""
    
    def __init__(self, infrastructure: Dict):
        self.infrastructure = infrastructure
        self.devices = infrastructure.get("devices", [])
        self.organization = infrastructure.get("organization", "Неизвестная организация")
        self.network_analyzer = NetworkAnalyzer(infrastructure)
        self.recommendations = {
            "trust_zones_elimination": [],      # 3.1 Устранение доверенных зон
            "minimal_privileges": [],           # 3.2 Минимальные привилегии
            "isolated_segments": [],            # 3.3 Изолированные сегменты
            "physical_access_isolation": [],    # 3.4 Изоляция физического доступа
            "traffic_inspection": [],           # 3.5 Сквозной контроль трафика
            "new_equipment": [],                # Новое оборудование
            "configuration_commands": [],       # Команды настройки
            "security_risks": []                # Выявленные риски
        }
    
    def analyze_infrastructure(self) -> Dict:
        """Проанализировать инфраструктуру и сгенерировать рекомендации по сегментации"""
        print("\n" + "="*80)
        print("ЭТАП 3: АНАЛИЗ И ПЛАНИРОВАНИЕ СЕГМЕНТАЦИИ СЕТИ")
        print("="*80)
        
        # Собираем информацию о текущей сети
        print("\nАНАЛИЗ ТЕКУЩЕЙ СЕТЕВОЙ ТОПОЛОГИИ...")
        current_analysis = self._analyze_current_network()
        
        # Генерируем рекомендации по всем подэтапам
        print("\nГЕНЕРАЦИЯ РЕКОМЕНДАЦИЙ...")
        
        # 3.1 Устранение концепции доверенных зон
        self._analyze_trust_zones(current_analysis)
        
        # 3.2 Минимальные привилегии
        self._analyze_minimal_privileges(current_analysis)
        
        # 3.3 Изолированные сегменты
        self._analyze_isolated_segments(current_analysis)
        
        # 3.4 Изоляция устройств с физическим доступом
        self._analyze_physical_access()
        
        # 3.5 Сквозной контроль трафика
        self._analyze_traffic_inspection(current_analysis)
        
        # Анализ рисков
        self.recommendations["security_risks"] = self.network_analyzer.analyze_security_risks()
        
        return self.recommendations
    
    def _analyze_current_network(self) -> Dict:
        """Проанализировать текущую сетевую инфраструктуру"""
        analysis = {
            "total_devices": len(self.devices),
            "segments": [],
            "network_equipment": self.network_analyzer.topology.network_equipment,
            "connections_count": len(self.network_analyzer.topology.connections),
            "current_vlans": {}
        }
        
        # Анализируем текущие сегменты
        print("\n  Определение текущих групп устройств...")
        for segment in self.network_analyzer.topology.segments:
            segment_info = {
                "name": segment.name,
                "security_level": segment.security_level.value,
                "device_count": len(segment.device_ids),
                "devices": [f"{d.get('manufacturer')} {d.get('model')}" 
                           for d in self.network_analyzer.get_segment_devices(segment.id)][:5]  # Показываем первые 5
            }
            analysis["segments"].append(segment_info)
        
        # Анализируем сетевое оборудование
        print(f"\n  Обнаружено сетевого оборудования: {len(analysis['network_equipment'])}")
        for eq in analysis['network_equipment'][:3]:  # Показываем первые 3
            print(f"    • {eq['type']}: {eq['manufacturer']} {eq['model']}")
        
        return analysis
    
    def _analyze_trust_zones(self, current_analysis: Dict):
        """3.1 Устранить концепцию «доверенных зон»"""
        print("\n[3.1] АНАЛИЗ КОНЦЕПЦИИ ДОВЕРЕННЫХ ЗОН")
        print("-"*40)
        
        # Основные принципы устранения доверенных зон
        principles = [
            "Отказ от концепции 'внутренняя сеть = безопасная сеть'",
            "Рассмотрение всех внутренних ресурсов как потенциально опасных",
            "Применение политик безопасности ко всему трафику, независимо от источника",
            "Фокус на защите ресурсов, а не периметра"
        ]
        
        for principle in principles:
            self.recommendations["trust_zones_elimination"].append({
                "type": "Принцип",
                "content": principle
            })
        
        # Конкретные шаги для организации
        steps = [
            {
                "step": "1. Идентификация текущих доверенных зон",
                "actions": [
                    "Составить карту всех сетевых сегментов",
                    "Определить устройства, считающиеся 'доверенными'",
                    "Проанализировать логи доступа для выявления неявных доверий"
                ]
            },
            {
                "step": "2. Внедрение микросегментации",
                "actions": [
                    "Разделить сеть на минимальные логические сегменты",
                    "Каждое устройство или группа устройств в отдельном сегменте",
                    "Использование VLAN, VXLAN или SDN технологий"
                ]
            },
            {
                "step": "3. Настройка политик доступа по умолчанию",
                "actions": [
                    "Установить политику 'Deny All' по умолчанию",
                    "Разрешать только необходимые соединения",
                    "Использовать whitelist вместо blacklist подход"
                ]
            },
            {
                "step": "4. Внедрение контроля сессий",
                "actions": [
                    "Каждая сессия должна аутентифицироваться",
                    "Временные ограничения для сессий доступа",
                    "Мониторинг аномальной активности"
                ]
            }
        ]
        
        for step_info in steps:
            self.recommendations["trust_zones_elimination"].append({
                "type": "Шаг реализации",
                "step": step_info["step"],
                "actions": step_info["actions"]
            })
        
        # Рекомендации по оборудованию
        equipment_recommendations = [
            {
                "type": "Программное обеспечение",
                "name": "Cisco Identity Services Engine (ISE)",
                "purpose": "Политики доступа на основе контекста",
                "cost": "от 2,000,000 руб."
            },
            {
                "type": "Оборудование",
                "name": "Palo Alto Networks Next-Gen Firewall",
                "purpose": "Применение политик на уровне приложений",
                "cost": "от 1,500,000 руб."
            },
            {
                "type": "Решение",
                "name": "VMware NSX",
                "purpose": "Микросегментация в программно-определяемых сетях",
                "cost": "от 3,000,000 руб."
            }
        ]
        
        for eq in equipment_recommendations:
            self.recommendations["trust_zones_elimination"].append({
                "type": "Оборудование/ПО",
                "name": eq["name"],
                "purpose": eq["purpose"],
                "cost": eq["cost"]
            })
    
    def _analyze_minimal_privileges(self, current_analysis: Dict):
        """3.2 Ограничить взаимодействие по принципу минимальных привилегий"""
        print("\n[3.2] АНАЛИЗ ПРИНЦИПА МИНИМАЛЬНЫХ ПРИВИЛЕГИЙ")
        print("-"*40)
        
        # Анализируем каждое устройство и его необходимые привилегии
        for device in self.devices:
            device_id = device["id"]
            device_type = device.get("type", "")
            manufacturer = device.get("manufacturer", "")
            model = device.get("model", "")
            protocols = device.get("protocols", [])
            
            # Определяем необходимые привилегии на основе типа устройства
            privileges = self._determine_required_privileges(device)
            
            # Формируем рекомендации для устройства
            device_recommendation = {
                "device_id": device_id,
                "device": f"{manufacturer} {model}",
                "type": device_type,
                "required_privileges": privileges["required"],
                "forbidden_privileges": privileges["forbidden"],
                "access_rules": [],
                "special_requirements": []
            }
            
            # Генерируем правила доступа
            if "камера" in device_type.lower():
                device_recommendation["access_rules"].append(
                    "Разрешить исходящий RTSP/RTP только к NVR серверу (порт 554)"
                )
                device_recommendation["access_rules"].append(
                    "Запретить любой входящий трафик, кроме управления с доверенных хостов"
                )
                device_recommendation["special_requirements"].append(
                    "Использовать отдельный VLAN для видео трафика"
                )
            
            elif "датчик" in device_type.lower():
                device_recommendation["access_rules"].append(
                    "Разрешить исходящий MQTT только к шлюзу (порт 1883 с TLS)"
                )
                device_recommendation["access_rules"].append(
                    "Запретить все входящие соединения"
                )
                device_recommendation["special_requirements"].append(
                    "Ограничить скорость передачи данных для предотвращения DDoS"
                )
            
            elif "маршрутизатор" in device_type.lower() or "коммутатор" in device_type.lower():
                device_recommendation["access_rules"].append(
                    "Разрешить SSH/HTTPS только с управляющего сегмента"
                )
                device_recommendation["access_rules"].append(
                    "Запретить ICMP ping извне управляющего сегмента"
                )
                device_recommendation["special_requirements"].append(
                    "Использовать TACACS+/RADIUS для аутентификации администраторов"
                )
            
            # Для критических устройств особые требования
            if device.get("critical", False):
                device_recommendation["special_requirements"].append(
                    "Вести полный лог всех сетевых соединений"
                )
                device_recommendation["special_requirements"].append(
                    "Реализовать гео-ограничение (только из РФ)"
                )
            
            self.recommendations["minimal_privileges"].append(device_recommendation)
        
        # Общие рекомендации
        general_recommendations = [
            {
                "type": "Методология",
                "title": "Zero Trust Network Access (ZTNA)",
                "description": "Предоставление доступа к приложениям, а не к сети",
                "implementation": "Внедрение решений типа Zscaler Private Access или Cloudflare Zero Trust"
            },
            {
                "type": "Технология",
                "title": "Применение политик на уровне приложений (Layer 7)",
                "description": "Контроль не только портов/IP, но и содержимого трафика",
                "implementation": "Настройка Next-Gen Firewall с deep packet inspection"
            },
            {
                "type": "Процесс",
                "title": "Регулярный пересмотр привилегий",
                "description": "Ежеквартальная проверка и обновление правил доступа",
                "implementation": "Внедрение системы управления привилегиями (PAM)"
            }
        ]
        
        for rec in general_recommendations:
            self.recommendations["minimal_privileges"].append({
                "type": "Общая рекомендация",
                "category": rec["type"],
                "title": rec["title"],
                "description": rec["description"],
                "implementation": rec["implementation"]
            })
    
    def _determine_required_privileges(self, device: Dict) -> Dict:
        """Определить необходимые привилегии для устройства"""
        device_type = device.get("type", "").lower()
        protocols = device.get("protocols", [])
        
        required = []
        forbidden = []
        
        # Базовые привилегии для всех устройств
        forbidden.extend([
            "Доступ к интернету (разрешать только через прокси)",
            "Исходящие соединения на нестандартные порты",
            "Доступ к административным интерфейсам других устройств"
        ])
        
        # Специфические привилегии
        if "камера" in device_type:
            required.extend([
                "Исходящий RTSP/RTP на порт 554 к NVR",
                "Исходящий HTTP/HTTPS для управления",
                "Получение времени от NTP сервера"
            ])
            forbidden.extend([
                "Доступ к корпоративной сети",
                "Входящие соединения из интернета",
                "Доступ к системам хранения данных"
            ])
        
        elif "датчик" in device_type:
            required.extend([
                "Исходящий MQTT на порт 1883/8883 к шлюзу",
                "Исходящий HTTP для отправки данных",
                "Получение конфигурации от сервера управления"
            ])
            forbidden.extend([
                "Прямой доступ к базам данных",
                "Исходящая почта (SMTP)",
                "Доступ к системам управления"
            ])
        
        elif any(x in device_type for x in ["маршрутизатор", "коммутатор", "фаервол"]):
            required.extend([
                "SSH/HTTPS доступ с управляющего сегмента",
                "SNMP опрос системой мониторинга",
                "Доступ к NTP серверам"
            ])
            forbidden.extend([
                "Доступ из интернета без VPN",
                "Telnet (использовать только SSH)",
                "Нешифрованные протоколы управления"
            ])
        
        return {
            "required": required,
            "forbidden": forbidden
        }
    
    def _analyze_isolated_segments(self, current_analysis: Dict):
        """3.3 Реализовать изолированные сегменты"""
        print("\n[3.3] АНАЛИЗ ИЗОЛИРОВАННЫХ СЕГМЕНТОВ")
        print("-"*40)
        
        # Анализируем текущие сегменты и предлагаем улучшения
        for segment in self.network_analyzer.topology.segments:
            devices = self.network_analyzer.get_segment_devices(segment.id)
            
            segment_analysis = {
                "segment_id": segment.id,
                "segment_name": segment.name,
                "security_level": segment.security_level.value,
                "current_devices": len(devices),
                "recommended_isolation": self._get_isolation_level(segment.security_level),
                "firewall_rules": [],
                "special_measures": []
            }
            
            # Генерируем правила фаервола для сегмента
            segment_analysis["firewall_rules"] = self._generate_firewall_rules(segment)
            
            # Особые меры для разных типов сегментов
            if segment.security_level == SecurityLevel.KII_CRITICAL:
                segment_analysis["special_measures"].extend([
                    "Физическая изоляция сети (air gap)",
                    "Использование односторонних шлюзов (data diodes)",
                    "Полный запрет исходящего интернет-трафика",
                    "Ежедневный аудит логов доступа"
                ])
            
            elif segment.security_level == SecurityLevel.PHYSICAL_ACCESS:
                segment_analysis["special_measures"].extend([
                    "Использование портов с 802.1X аутентификацией",
                    "MAC-фильтрация на коммутаторах",
                    "Ограничение скорости передачи данных",
                    "Сегментация по времени доступа"
                ])
            
            elif segment.security_level == SecurityLevel.IOT_UNTRUSTED:
                segment_analysis["special_measures"].extend([
                    "Прозрачный прокси для анализа трафика",
                    "Sandbox для анализа подозрительных устройств",
                    "Автоматическая блокировка при обнаружении аномалий",
                    "Ограничение доступа только необходимым ресурсам"
                ])
            
            self.recommendations["isolated_segments"].append(segment_analysis)
        
        # Рекомендации по реализации изоляции
        implementation_recommendations = [
            {
                "technology": "VLAN",
                "description": "Логическая изоляция на уровне 2",
                "recommendation": "Использовать отдельные VLAN для каждого типа устройств",
                "equipment": "Коммутаторы с поддержкой 802.1Q"
            },
            {
                "technology": "VRF",
                "description": "Изоляция на уровне 3 (виртуальные маршрутизаторы)",
                "recommendation": "Для критических систем использовать отдельные VRF",
                "equipment": "Маршрутизаторы Cisco, Juniper"
            },
            {
                "technology": "SD-WAN",
                "description": "Программно-определяемая изоляция",
                "recommendation": "Для распределенных филиалов и облачных ресурсов",
                "equipment": "Решения Viptela, Velocloud"
            },
            {
                "technology": "Микросегментация",
                "description": "Изоляция на уровне каждого устройства",
                "recommendation": "Для высокозащищенных сред и контейнеров",
                "equipment": "VMware NSX, Cisco ACI"
            }
        ]
        
        for tech in implementation_recommendations:
            self.recommendations["isolated_segments"].append({
                "type": "Технология изоляции",
                "technology": tech["technology"],
                "description": tech["description"],
                "recommendation": tech["recommendation"],
                "required_equipment": tech["equipment"]
            })
    
    def _get_isolation_level(self, security_level: SecurityLevel) -> str:
        """Определить уровень изоляции для сегмента"""
        isolation_levels = {
            SecurityLevel.KII_CRITICAL: "ПОЛНАЯ ФИЗИЧЕСКАЯ ИЗОЛЯЦИЯ",
            SecurityLevel.KII_HIGH: "ВЫСОКАЯ (логическая + физическая)",
            SecurityLevel.INDUSTRIAL: "ВЫСОКАЯ (отдельная сеть)",
            SecurityLevel.CORPORATE: "СРЕДНЯЯ (VLAN + фаервол)",
            SecurityLevel.IOT_TRUSTED: "СРЕДНЯЯ (VLAN + ограничения)",
            SecurityLevel.IOT_UNTRUSTED: "ВЫСОКАЯ (DMZ-like)",
            SecurityLevel.PHYSICAL_ACCESS: "ВЫСОКАЯ (портовая безопасность)",
            SecurityLevel.GUEST: "НИЗКАЯ (ограниченный доступ)",
            SecurityLevel.DMZ: "СРЕДНЯЯ (демилитаризованная зона)",
            SecurityLevel.MANAGEMENT: "ВЫСОКАЯ (строгий контроль)"
        }
        return isolation_levels.get(security_level, "СРЕДНЯЯ")
    
    def _generate_firewall_rules(self, segment: NetworkSegment) -> List[str]:
        """Сгенерировать правила фаервола для сегмента"""
        rules = []
        
        # Базовые правила для всех сегментов
        rules.append("DENY ALL (правило по умолчанию)")
        
        if segment.security_level == SecurityLevel.KII_CRITICAL:
            rules.extend([
                "ALLOW: Управление с сегмента MANAGEMENT (порты 22, 443, 161)",
                "ALLOW: NTP синхронизация с внутренних серверов (порт 123)",
                "DENY: Любой доступ из интернета",
                "DENY: Исходящий трафик в интернет",
                "ALLOW: Репликация данных на резервный сервер (специфичные порты)"
            ])
        
        elif segment.security_level == SecurityLevel.IOT_UNTRUSTED:
            rules.extend([
                "ALLOW: Исходящий MQTT к шлюзу (порт 8883 с TLS)",
                "ALLOW: Получение обновлений с внутреннего сервера (порт 443)",
                "DENY: Любой входящий трафик, кроме управления",
                "DENY: Доступ к корпоративной сети",
                "ALLOW: NTP только с внутренних серверов"
            ])
        
        elif segment.security_level == SecurityLevel.PHYSICAL_ACCESS:
            rules.extend([
                "ALLOW: 802.1X аутентификация (порты 1812, 1813)",
                "ALLOW: DHCP (порты 67, 68) только с доверенных серверов",
                "DENY: Любой трафик при неудачной аутентификации",
                "ALLOW: Ограниченный доступ к интернету через прокси",
                "DENY: P2P протоколы и torrent"
            ])
        
        return rules
    
    def _analyze_physical_access(self):
        """3.4 Логически отделить устройства с физическим доступом"""
        print("\n[3.4] АНАЛИЗ УСТРОЙСТВ С ФИЗИЧЕСКИМ ДОСТУПОМ")
        print("-"*40)
        
        # Находим устройства с физическим доступом
        physical_devices = [d for d in self.devices if d.get("physical_access", False)]
        
        if not physical_devices:
            self.recommendations["physical_access_isolation"].append({
                "status": "Информация",
                "message": "Устройства с физическим доступом не обнаружены"
            })
            return
        
        # Анализируем каждое устройство
        for device in physical_devices:
            device_analysis = {
                "device_id": device["id"],
                "device": f"{device['manufacturer']} {device['model']}",
                "type": device.get("type", ""),
                "location_risk": self._assess_location_risk(device),
                "physical_security_measures": [],
                "network_security_measures": [],
                "monitoring_recommendations": []
            }
            
            # Меры физической безопасности
            if device.get("critical", False):
                device_analysis["physical_security_measures"].extend([
                    "Установка в запираемом шкафу/помещении",
                    "Сигнализация при открытии",
                    "Видеонаблюдение за устройством",
                    "Контроль доступа по картам/биометрии"
                ])
            else:
                device_analysis["physical_security_measures"].extend([
                    "Фиксация устройства (anti-theft)",
                    "Наклейки с предупреждениями",
                    "Регулярный физический осмотр"
                ])
            
            # Меры сетевой безопасности
            device_analysis["network_security_measures"].extend([
                "Портовая безопасность (802.1X, MAC-фильтрация)",
                "Ограничение скорости на порту",
                "Изоляция в отдельном VLAN",
                "Запрет меж-VLAN маршрутизации"
            ])
            
            # Рекомендации по мониторингу
            device_analysis["monitoring_recommendations"].extend([
                "Мониторинг подключений к порту",
                "Анализ MAC-адресов",
                "Детектирование несанкционированных устройств",
                "Оповещение при изменении конфигурации"
            ])
            
            self.recommendations["physical_access_isolation"].append(device_analysis)
        
        # Общие рекомендации
        general_recommendations = [
            {
                "category": "Оборудование",
                "recommendation": "Установить управляемые коммутаторы с поддержкой 802.1X",
                "examples": "Cisco Catalyst 2960X, HP Aruba 2930F"
            },
            {
                "category": "ПО",
                "recommendation": "Внедрить систему управления сетевым доступом (NAC)",
                "examples": "Cisco ISE, ForeScout CounterACT"
            },
            {
                "category": "Процедуры",
                "recommendation": "Вести журнал физического доступа к устройствам",
                "examples": "Журнал посещений, система контроля доступа"
            }
        ]
        
        for rec in general_recommendations:
            self.recommendations["physical_access_isolation"].append({
                "type": "Общая рекомендация",
                "category": rec["category"],
                "recommendation": rec["recommendation"],
                "examples": rec["examples"]
            })
    
    def _assess_location_risk(self, device: Dict) -> str:
        """Оценить риск расположения устройства"""
        device_type = device.get("type", "").lower()
        
        if "банкомат" in device_type or "терминал" in device_type:
            return "ВЫСОКИЙ (общедоступное место)"
        elif "камера" in device_type and device.get("physical_access", False):
            return "ВЫСОКИЙ (возможность физического вмешательства)"
        elif "датчик" in device_type and "уличный" in device_type.lower():
            return "СРЕДНИЙ (внешняя установка)"
        elif "роутер" in device_type or "коммутатор" in device_type:
            return "СРЕДНИЙ (техническое помещение)"
        else:
            return "НИЗКИЙ (контролируемое помещение)"
    
    def _analyze_traffic_inspection(self, current_analysis: Dict):
        """3.5 Настроить сквозной контроль трафика"""
        print("\n[3.5] АНАЛИЗ СКВОЗНОГО КОНТРОЛЯ ТРАФИКА")
        print("-"*40)
        
        # Анализ текущих возможностей
        network_equipment = current_analysis["network_equipment"]
        has_advanced_capabilities = any(
            "Firewall/ACL" in eq.get("capabilities", []) 
            for eq in network_equipment
        )
        
        analysis = {
            "current_capabilities": "ОГРАНИЧЕННЫЕ" if not has_advanced_capabilities else "ДОСТАТОЧНЫЕ",
            "recommended_technologies": [],
            "inspection_points": [],
            "implementation_steps": []
        }
        
        # Рекомендуемые технологии
        technologies = [
            {
                "name": "Next-Generation Firewall (NGFW)",
                "vendor": "Palo Alto Networks, Fortinet, Check Point",
                "capabilities": "Глубокий анализ пакетов (DPI), Sandboxing, SSL инспекция",
                "placement": "На границе сети и между критическими сегментами"
            },
            {
                "name": "Intrusion Prevention System (IPS)",
                "vendor": "Cisco Firepower, McAfee, Trend Micro",
                "capabilities": "Обнаружение и предотвращение атак, сигнатурный анализ",
                "placement": "Внутри критических сегментов"
            },
            {
                "name": "Network Traffic Analysis (NTA)",
                "vendor": "Darktrace, ExtraHop, Vectra",
                "capabilities": "Анализ поведения, обнаружение аномалий, машинное обучение",
                "placement": "Зеркалирование трафика (SPAN порты)"
            },
            {
                "name": "Secure Web Gateway (SWG)",
                "vendor": "Zscaler, Netskope, Symantec",
                "capabilities": "Фильтрация веб-трафика, защита от угроз",
                "placement": "В облаке или на границе сети"
            }
        ]
        
        for tech in technologies:
            analysis["recommended_technologies"].append(tech)
        
        # Точки инспекции
        segments = self.network_analyzer.topology.segments
        for segment in segments:
            if segment.security_level in [SecurityLevel.KII_CRITICAL, SecurityLevel.KII_HIGH, SecurityLevel.IOT_UNTRUSTED]:
                analysis["inspection_points"].append({
                    "segment": segment.name,
                    "inspection_type": "ПОЛНАЯ ИНСПЕКЦИЯ",
                    "recommendations": [
                        f"NGFW между {segment.name} и другими сегментами",
                        "SSL/TLS декрипция для анализа содержимого",
                        "Анализ поведения (UEBA) для аномальной активности"
                    ]
                })
        
        # Шаги реализации
        implementation_steps = [
            {
                "phase": "Фаза 1 (1-2 месяца)",
                "actions": [
                    "Установка NGFW на границе сети",
                    "Настройка базовых политик для критических сегментов",
                    "Включение журналирования всех блокировок"
                ]
            },
            {
                "phase": "Фаза 2 (3-4 месяца)",
                "actions": [
                    "Внедрение SSL инспекции для внешнего трафика",
                    "Настройка IPS для критических систем",
                    "Интеграция с SIEM системой"
                ]
            },
            {
                "phase": "Фаза 3 (5-6 месяцев)",
                "actions": [
                    "Полное внедрение микросегментации",
                    "Настройка поведенческого анализа",
                    "Автоматизация реагирования на инциденты"
                ]
            }
        ]
        
        analysis["implementation_steps"] = implementation_steps
        
        # Команды настройки для типового оборудования
        config_commands = [
            {
                "equipment": "Cisco ASA/Firepower",
                "purpose": "Настройка инспекции трафика",
                "commands": [
                    "access-list INSIDE_TO_OUTSIDE extended permit ip any any",
                    "class-map INSPECTION_CLASS",
                    " match access-list INSIDE_TO_OUTSIDE",
                    "policy-map GLOBAL_POLICY",
                    " class INSPECTION_CLASS",
                    "  inspect ftp",
                    "  inspect h323 h225",
                    "  inspect http",
                    "  inspect netbios",
                    "  inspect rpc",
                    "  inspect rtsp",
                    "  inspect skinny",
                    "  inspect esmtp",
                    "  inspect sqlnet",
                    "  inspect sunrpc",
                    "  inspect tftp",
                    "  inspect sip",
                    "  inspect xdmcp"
                ]
            },
            {
                "equipment": "MikroTik RouterOS",
                "purpose": "Включение глубокой инспекции",
                "commands": [
                    "/ip firewall layer7-protocol add name=skype regexp=\"^.+(skype|microsoft).+$\"",
                    "/ip firewall filter add chain=forward layer7-protocol=skype action=drop",
                    "/ip firewall filter add chain=forward protocol=tcp dst-port=80,443 action=add-src-to-address-list \\",
                    "  address-list=web-traffic address-list-timeout=1d",
                    "/tool sniffer quick protocol=tcp port=80,443"
                ]
            }
        ]
        
        self.recommendations["traffic_inspection"] = analysis
        self.recommendations["configuration_commands"] = config_commands
    
    def generate_report(self) -> str:
        """Сгенерировать отчет по этапу 3"""
        report = []
        report.append("\n" + "="*80)
        report.append("ОТЧЕТ ПО ЭТАПУ 3: СЕГМЕНТАЦИЯ СЕТИ")
        report.append("="*80)
        
        # Статистика
        total_devices = len(self.devices)
        segments_count = len(self.network_analyzer.topology.segments)
        physical_devices = sum(1 for d in self.devices if d.get("physical_access", False))
        
        report.append(f"\nОБЩАЯ СТАТИСТИКА:")
        report.append(f"  Всего устройств: {total_devices}")
        report.append(f"  Предложено сегментов: {segments_count}")
        report.append(f"  Устройств с физическим доступом: {physical_devices}")
        
        # 3.1 Устранение доверенных зон
        report.append("\n\n3.1. УСТРАНЕНИЕ КОНЦЕПЦИИ «ДОВЕРЕННЫХ ЗОН»")
        report.append("-"*60)
        
        for rec in self.recommendations["trust_zones_elimination"][:5]:  # Первые 5
            if rec["type"] == "Принцип":
                report.append(f"\n{rec['content']}")
            elif rec["type"] == "Шаг реализации":
                report.append(f"\n{rec['step']}:")
                for action in rec["actions"]:
                    report.append(f"  • {action}")
        
        # 3.2 Минимальные привилегии
        report.append("\n\n3.2. МИНИМАЛЬНЫЕ ПРИВИЛЕГИИ")
        report.append("-"*60)
        
        # Показываем примеры для нескольких типов устройств
        device_types_shown = set()
        for rec in self.recommendations["minimal_privileges"]:
            if isinstance(rec, dict) and "device" in rec:
                device_type = rec["type"]
                if device_type not in device_types_shown:
                    device_types_shown.add(device_type)
                    report.append(f"\n📱 {device_type}:")
                    report.append(f"  Устройство: {rec['device']}")
                    if rec.get("required_privileges"):
                        report.append("  Необходимые привилегии:")
                        for priv in rec["required_privileges"][:3]:  # Первые 3
                            report.append(f"    ✓ {priv}")
                    if rec.get("access_rules"):
                        report.append("  Правила доступа:")
                        for rule in rec["access_rules"][:2]:  # Первые 2
                            report.append(f"    • {rule}")
        
        # 3.3 Изолированные сегменты
        report.append("\n\n3.3. ИЗОЛИРОВАННЫЕ СЕГМЕНТЫ")
        report.append("-"*60)
        
        for segment in self.network_analyzer.topology.segments[:4]:  # Первые 4 сегмента
            report.append(f"\n{segment.name}:")
            report.append(f"  Уровень безопасности: {segment.security_level.value}")
            report.append(f"  Уровень изоляции: {self._get_isolation_level(segment.security_level)}")
            report.append(f"  Количество устройств: {len(segment.device_ids)}")
            
            # Правила фаервола
            rules = self._generate_firewall_rules(segment)
            if rules:
                report.append("  Ключевые правила фаервола:")
                for rule in rules[:3]:  # Первые 3 правила
                    report.append(f"    • {rule}")
        
        # 3.4 Физический доступ
        report.append("\n\n3.4. ИЗОЛЯЦИЯ УСТРОЙСТВ С ФИЗИЧЕСКИМ ДОСТУПОМ")
        report.append("-"*60)
        
        physical_devices_list = [d for d in self.devices if d.get("physical_access", False)]
        if physical_devices_list:
            report.append(f"\nОбнаружено устройств: {len(physical_devices_list)}")
            for device in physical_devices_list[:3]:  # Первые 3
                report.append(f"\n{device['manufacturer']} {device['model']}:")
                report.append(f"  Тип: {device.get('type')}")
                report.append(f"  Уровень риска: {self._assess_location_risk(device)}")
                report.append("  Рекомендуемые меры:")
                report.append("    • Портовая безопасность (802.1X)")
                report.append("    • Отдельный VLAN")
                report.append("    • MAC-фильтрация")
        else:
            report.append("\nУстройства с физическим доступом не обнаружены")
        
        # 3.5 Сквозной контроль трафика
        report.append("\n\n3.5. СКВОЗНОЙ КОНТРОЛЬ ТРАФИКА")
        report.append("-"*60)
        
        inspection = self.recommendations.get("traffic_inspection", {})
        if inspection:
            report.append(f"\nТекущие возможности: {inspection.get('current_capabilities', 'НЕОПРЕДЕЛЕНЫ')}")
            
            report.append("\nРекомендуемые технологии:")
            for tech in inspection.get("recommended_technologies", [])[:2]:  # Первые 2
                report.append(f"  • {tech['name']} ({tech['vendor']})")
                report.append(f"    Назначение: {tech['capabilities']}")
            
            report.append("\nЭтапы внедрения:")
            for phase in inspection.get("implementation_steps", []):
                report.append(f"\n  {phase['phase']}:")
                for action in phase["actions"]:
                    report.append(f"    • {action}")
        
        # Выявленные риски
        report.append("\n\nВЫЯВЛЕННЫЕ РИСКИ БЕЗОПАСНОСТИ")
        report.append("-"*60)
        
        risks = self.recommendations.get("security_risks", [])
        if risks:
            for risk in risks[:5]:  # Первые 5 рисков
                report.append(f"\n[{risk['type']}] {risk['description']}")
                report.append(f"  Рекомендация: {risk['recommendation']}")
        else:
            report.append("\nКритических рисков не обнаружено")
        
        # Нормативные требования
        report.append("\n\nНОРМАТИВНЫЕ ТРЕБОВАНИЯ К СЕГМЕНТАЦИИ")
        report.append("-"*60)
        report.append("• ФСТЭК Приказ №239: Требования к разделению сетей")
        report.append("• ГОСТ Р 57580.1-2017: Сегментация сетей КИИ")
        report.append("• PCI DSS: Разделение сетей для платежных систем")
        report.append("• NIST SP 800-41: Рекомендации по фаерволам")
        report.append("• ISO/IEC 27033: Безопасность сетевой инфраструктуры")
        
        # Ориентировочная стоимость
        report.append("\n\nОРИЕНТИРОВОЧНАЯ СТОИМОСТЬ ВНЕДРЕНИЯ")
        report.append("-"*60)
        report.append("• Оборудование (NGFW, коммутаторы): от 2,000,000 руб.")
        report.append("• Программное обеспечение: от 1,500,000 руб.")
        report.append("• Услуги внедрения: от 1,000,000 руб.")
        report.append("• Обучение персонала: от 500,000 руб.")
        report.append("• ИТОГО: от 5,000,000 руб.")
        
        return "\n".join(report)
    
    def save_report_to_file(self, filename: str = "segmentation_report.txt"):
        """Сохранить отчет в файл"""
        report_text = self.generate_report()
        
        # Создаем директорию reports если её нет
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        filepath = reports_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report_text)
        
        print(f"\nОтчет сохранен в файл: {filepath}")
        return str(filepath)
    
    def print_summary(self):
        """Вывести краткое содержание"""
        print("\n" + "="*80)
        print("КРАТКОЕ СОДЕРЖАНИЕ РЕКОМЕНДАЦИЙ ПО СЕГМЕНТАЦИИ")
        print("="*80)
        
        segments = self.network_analyzer.topology.segments
        physical_devices = sum(1 for d in self.devices if d.get("physical_access", False))
        
        print(f"\nСТАТИСТИКА:")
        print(f"  Всего устройств: {len(self.devices)}")
        print(f"  Предложено сегментов: {len(segments)}")
        print(f"  Устройств с физическим доступом: {physical_devices}")
        
        print(f"\nКЛЮЧЕВЫЕ СЕГМЕНТЫ:")
        for segment in segments[:3]:  # Первые 3 сегмента
            print(f"  • {segment.name}: {len(segment.device_ids)} устройств, "
                  f"уровень: {segment.security_level.value}")
        
        print(f"\nКРИТИЧЕСКИЕ РИСКИ:")
        risks = self.recommendations.get("security_risks", [])
        critical_risks = [r for r in risks if r["type"] == "КРИТИЧЕСКИЙ"]
        if critical_risks:
            for risk in critical_risks[:2]:
                print(f"  • {risk['description'][:80]}...")
        else:
            print("  Не обнаружено")
        
        print(f"\nОСНОВНЫЕ РЕКОМЕНДАЦИИ:")
        print("  1. Внедрить микросегментацию на основе Zero Trust")
        print("  2. Установить NGFW между критическими сегментами")
        print("  3. Реализовать 802.1X для устройств с физическим доступом")
        print("  4. Настроить сквозную инспекцию SSL трафика")
        print("  5. Внедрить систему управления сетевым доступом (NAC)")