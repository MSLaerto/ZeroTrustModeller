"""
Модуль для генерации рекомендаций по внедрению шифрования (Этап 2)
"""

import json
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

class EncryptionPlanner:
    """Планировщик внедрения шифрования для IoT-инфраструктуры"""
    
    def __init__(self, infrastructure: Dict):
        self.infrastructure = infrastructure
        self.devices = infrastructure.get("devices", [])
        self.organization = infrastructure.get("organization", "Неизвестная организация")
        self.recommendations = {
            "crypto_standards": [],
            "secure_channels": [],
            "key_management": [],
            "storage_encryption": [],
            "new_devices_to_add": []
        }
    
    def analyze_infrastructure(self) -> Dict:
        """Проанализировать инфраструктуру и сгенерировать рекомендации"""
        print("\n" + "="*60)
        print("ЭТАП 2: АНАЛИЗ ШИФРОВАНИЯ ДАННЫХ")
        print("="*60)
        
        # 2.1. Выбор криптостандартов
        self._analyze_crypto_standards()
        
        # 2.2. Настройка защищённых каналов
        self._analyze_secure_channels()
        
        # 2.3. Система генерации и хранения ключей
        self._analyze_key_management()
        
        # 2.4. Шифрование хранилищ
        self._analyze_storage_encryption()
        
        return self.recommendations
    
    def _analyze_crypto_standards(self):
        """2.1. Выбрать криптостандарты для защиты передаваемых данных"""
        print("\n[2.1] АНАЛИЗ КРИПТОСТАНДАРТОВ")
        print("-"*40)
        
        for device in self.devices:
            device_id = device.get("id")
            manufacturer = device.get("manufacturer", "")
            model = device.get("model", "")
            has_encryption = device.get("encryption", False)
            can_change = device.get("can_change_protocols", "неизвестно")
            
            # Получаем рекомендации из этапа 1
            enc_rec = device.get("encryption_recommendation", {})
            recommended_algo = enc_rec.get("recommended_algorithm", "")
            needs_replacement = enc_rec.get("replacement_needed", False)
            
            recommendation = {
                "device_id": device_id,
                "device": f"{manufacturer} {model}",
                "current_encryption": "Есть" if has_encryption else "Нет",
                "can_change_protocols": can_change,
                "actions": [],
                "priority": "средний"
            }
            
            # Логика выбора алгоритма по блок-схеме
            if "Кузнечик" in recommended_algo or "Магма" in recommended_algo:
                if has_encryption:
                    if "Уже используется" in recommended_algo:
                        action = "Устройство уже использует отечественный алгоритм. Проверить актуальность версии ГОСТ."
                    else:
                        action = f"Заменить текущий алгоритм на {recommended_algo} (ГОСТ Р 34.12-2015/34.13-2015)"
                else:
                    action = f"Внедрить алгоритм {recommended_algo} (ГОСТ Р 34.12-2015/34.13-2015)"
                
                recommendation["actions"].append(action)
                
                if can_change == "нет":
                    recommendation["actions"].append("Устройство не поддерживает смену протоколов. Требуется шлюз шифрования.")
                    recommendation["priority"] = "высокий"
                    
            elif "ChaCha20" in recommended_algo or "Present80" in recommended_algo:
                if needs_replacement:
                    recommendation["actions"].append(
                        "ТРЕБУЕТСЯ ЗАМЕНА УСТРОЙСТВА. Невозможно установить отечественные алгоритмы. "
                        f"Временно использовать {recommended_algo} через шлюз шифрования."
                    )
                    recommendation["priority"] = "критический"
                    
                    # Предлагаем отечественную замену
                    replacement = self._get_replacement_suggestion(manufacturer, model)
                    if replacement:
                        recommendation["actions"].append(
                            f"Рекомендуемая замена: {replacement} (поддерживает ГОСТ)"
                        )
                else:
                    recommendation["actions"].append(
                        f"Использовать {recommended_algo} через TLS-шлюз. "
                        "Рассмотреть замену на устройство с поддержкой ГОСТ."
                    )
                    recommendation["priority"] = "высокий"
            
            # Для устройств КИИ особые требования
            if device.get("kii_category", 0) in [1, 2]:
                recommendation["actions"].append(
                    "Устройство КИИ! Требуется сертифицированное ПО шифрования ФСТЭК"
                )
                recommendation["priority"] = "критический"
            
            # Для импортного оборудования
            if manufacturer not in ["Овен", "Элвис-Нео", "Ростелеком", "Болид", "Киберлок"]:
                recommendation["actions"].append(
                    "Импортное оборудование. Проверить наличие backdoor. "
                    "Рассчитать срок замены на отечественное."
                )
            
            if recommendation["actions"]:
                self.recommendations["crypto_standards"].append(recommendation)
    
    def _analyze_secure_channels(self):
        """2.2. Настроить защищённые каналы между устройствами и серверами"""
        print("\n[2.2] АНАЛИЗ ЗАЩИЩЕННЫХ КАНАЛОВ СВЯЗИ")
        print("-"*40)
        
        # Группируем устройства по типам и группам взаимодействия
        groups = {}
        for device in self.devices:
            group = device.get("interaction_group", "default")
            if group not in groups:
                groups[group] = []
            groups[group].append(device)
        
        # Анализируем каждую группу
        for group_name, devices in groups.items():
            if len(devices) < 2:
                continue
                
            # Определяем центральное устройство (шлюз/маршрутизатор) в группе
            gateway = self._find_gateway_for_group(devices)
            
            recommendation = {
                "group": group_name,
                "devices": [f"{d.get('manufacturer')} {d.get('model')} (ID: {d.get('id')})" for d in devices],
                "gateway": gateway,
                "protocols": self._get_common_protocols(devices),
                "recommendations": []
            }
            
            # Основные рекомендации для группы
            if gateway:
                # Есть шлюз - настраиваем TLS-терминацию
                recommendation["recommendations"].append(
                    f"Настроить TLS 1.3 терминацию на шлюзе {gateway}. "
                    "Использовать сертификаты УЦ ФСТЭК."
                )
                recommendation["recommendations"].append(
                    "Настроить VPN между шлюзом и облачным сервером (IPsec/IKEv2 с ГОСТ алгоритмами)"
                )
            else:
                # Нет шлюза - рекомендуем добавить
                new_gateway = {
                    "type": "Маршрутизатор/шлюз",
                    "manufacturer": "MikroTik",
                    "model": "hEX S",
                    "purpose": f"TLS-терминация для группы {group_name}",
                    "config": "Настроить как VPN-шлюз с поддержкой ГОСТ"
                }
                self.recommendations["new_devices_to_add"].append(new_gateway)
                
                recommendation["recommendations"].append(
                    f"Добавить шлюз {new_gateway['manufacturer']} {new_gateway['model']} "
                    "для TLS-терминации и управления ключами"
                )
            
            # Для каждого устройства в группе
            for device in devices:
                if not device.get("encryption", False):
                    recommendation["recommendations"].append(
                        f"Для устройства {device.get('manufacturer')} {device.get('model')} "
                        "настроить TLS 1.2+ или использовать шлюз для терминации"
                    )
            
            # Проверка портов
            open_ports = self._get_open_ports(devices)
            if any(port in [80, 23, 21] for port in open_ports):
                recommendation["recommendations"].append(
                    "Обнаружены открытые незащищенные порты (80/HTTP, 23/Telnet, 21/FTP). "
                    "Закрыть или защитить через VPN."
                )
            
            self.recommendations["secure_channels"].append(recommendation)
    
    def _analyze_key_management(self):
        """2.3. Организовать систему генерации и безопасного хранения ключей"""
        print("\n[2.3] АНАЛИЗ СИСТЕМЫ УПРАВЛЕНИЯ КЛЮЧАМИ")
        print("-"*40)
        
        # Проверяем, есть ли устройства для HSM
        hsm_candidates = []
        for device in self.devices:
            if device.get("type") in ["Маршрутизатор", "Сервер", "Межсетевой экран"]:
                if device.get("compute_power") in ["средняя", "высокая"]:
                    hsm_candidates.append(device)
        
        if hsm_candidates:
            # Используем существующее устройство как HSM
            best_hsm = max(hsm_candidates, key=lambda x: 1 if x.get("compute_power") == "высокая" else 0)
            
            recommendation = {
                "hsm_device": f"{best_hsm.get('manufacturer')} {best_hsm.get('model')} (ID: {best_hsm.get('id')})",
                "type": "Программный HSM",
                "recommendations": [
                    "Установить КриптоПро CSP или ViPNet CryptoService",
                    "Интегрировать с УЦ ФСТЭК для выпуска сертификатов",
                    "Настроить политики ротации ключей: каждые 90 дней для КИИ, 180 дней для остальных",
                    "Резервное копирование ключей на изолированный носитель (Рутокен ЭЦП)"
                ]
            }
        else:
            # Рекомендуем добавить аппаратный HSM
            hsm_device = {
                "type": "Аппаратный модуль безопасности",
                "manufacturer": "Рутокен",
                "model": "Рутокен S3 3000",
                "purpose": "Хранение корневых ключей и сертификатов",
                "config": "Интеграция с PKI, поддержка ГОСТ Р 34.10-2012"
            }
            self.recommendations["new_devices_to_add"].append(hsm_device)
            
            recommendation = {
                "hsm_device": "Нет в инфраструктуре",
                "type": "Аппаратный HSM (рекомендуется)",
                "recommendations": [
                    f"Приобрести {hsm_device['manufacturer']} {hsm_device['model']}",
                    "Хранить в защищенном помещении с контролем доступа",
                    "Использовать для корневых ключей УЦ и ключей КИИ"
                ]
            }
        
        # Дополнительные рекомендации
        recommendation["recommendations"].extend([
            "Внедрить систему журналирования доступа к ключам (требование ФСТЭК №239)",
            "Разделить ключи по зонам ответственности (административные, пользовательские, системные)",
            "Для облачных сервисов использовать Key Management Service (KMS) с поддержкой ГОСТ"
        ])
        
        self.recommendations["key_management"].append(recommendation)
    
    def _analyze_storage_encryption(self):
        """2.4. Обеспечить шифрование хранилищ"""
        print("\n[2.4] АНАЛИЗ ШИФРОВАНИЯ ХРАНИЛИЩ")
        print("-"*40)
        
        storage_devices = []
        for device in self.devices:
            device_type = device.get("type", "")
            data_volume = device.get("data_volume", "")
            
            # Определяем устройства с хранилищами
            has_storage = False
            if any(word in device_type.lower() for word in ["сервер", "регистратор", "накопитель", "пк", "ноутбук"]):
                has_storage = True
            elif data_volume in ["средняя", "высокая"]:
                has_storage = True
            elif device.get("memory") == "высокая":
                has_storage = True
            
            if has_storage:
                storage_devices.append(device)
        
        for device in storage_devices:
            recommendation = {
                "device_id": device.get("id"),
                "device": f"{device.get('manufacturer')} {device.get('model')}",
                "storage_type": self._detect_storage_type(device),
                "recommendations": []
            }
            
            # Рекомендации в зависимости от типа хранилища
            storage_type = recommendation["storage_type"]
            
            if storage_type == "Встроенная память":
                if device.get("compute_power") in ["средняя", "высокая"]:
                    recommendation["recommendations"].append(
                        "Включить аппаратное шифрование диска (если поддерживается)"
                    )
                recommendation["recommendations"].append(
                    "Использовать программное шифрование (VeraCrypt с ГОСТ алгоритмами)"
                )
                
            elif storage_type == "Внешнее хранилище":
                recommendation["recommendations"].extend([
                    "Шифровать весь том при подключении",
                    "Использовать ключи от HSM, а не пароли",
                    "Для NAS: включить шифрование на уровне файловой системы"
                ])
                
            elif storage_type == "Облачное хранилище":
                recommendation["recommendations"].extend([
                    "Использовать провайдера с поддержкой ГОСТ (например, Selectel)",
                    "Включить шифрование на стороне клиента",
                    "Настроить синхронизацию ключей с локальным HSM"
                ])
            
            # Особые требования для критических устройств
            if device.get("critical", False):
                recommendation["recommendations"].append(
                    "КРИТИЧЕСКОЕ УСТРОЙСТВО! Обязательное шифрование томов с предзагрузочной аутентификацией"
                )
            
            # Для устройств КИИ
            if device.get("kii_category", 0) in [1, 2]:
                recommendation["recommendations"].append(
                    "Требуется сертифицированное СКЗИ ФСТЭК для шифрования"
                )
            
            self.recommendations["storage_encryption"].append(recommendation)
    
    def _get_replacement_suggestion(self, manufacturer: str, model: str) -> str:
        """Получить предложение по замене устройства на отечественный аналог"""
        replacements = {
            "Hikvision": "Элвис-Нео К-200 или РТК Камера Pro",
            "Dahua": "БезопасныйГород НВР-08",
            "Siemens": "ОВЕН ПЛК160 или ПЛК250",
            "Allen-Bradley": "ОВЕН ПЛК250",
            "Schneider Electric": "ОВЕН",
            "Cisco": "Qtech QSW-2800 или Eltex",
            "Fortinet": "Ростелеком Киберзащита",
            "Xiaomi": "Яндекс Розетка/Лампа",
            "TP-Link": "Ростелеком Умный дом",
            "Ubiquiti": "Eltex WAP"
        }
        
        for key, value in replacements.items():
            if key.lower() in manufacturer.lower():
                return value
        return "Российский аналог по спецификациям"
    
    def _find_gateway_for_group(self, devices: List[Dict]) -> str:
        """Найти шлюз для группы устройств"""
        for device in devices:
            if device.get("type") in ["Маршрутизатор", "Шлюз", "Межсетевой экран"]:
                return f"{device.get('manufacturer')} {device.get('model')} (ID: {device.get('id')})"
        return None
    
    def _get_common_protocols(self, devices: List[Dict]) -> List[str]:
        """Получить общие протоколы для группы устройств"""
        protocols = set()
        for device in devices:
            for protocol in device.get("protocols", []):
                protocols.add(protocol)
        return list(protocols)
    
    def _get_open_ports(self, devices: List[Dict]) -> List[int]:
        """Получить список открытых портов у устройств"""
        ports = []
        for device in devices:
            ports.extend(device.get("ports", []))
        return list(set(ports))
    
    def _detect_storage_type(self, device: Dict) -> str:
        """Определить тип хранилища устройства"""
        device_type = device.get("type", "").lower()
        
        if any(word in device_type for word in ["сервер", "пк", "ноутбук"]):
            return "Встроенная память"
        elif any(word in device_type for word in ["регистратор", "накопитель"]):
            return "Внешнее хранилище"
        elif device.get("data_volume") == "высокая" and device.get("memory") == "высокая":
            return "Облачное хранилище"
        else:
            return "Встроенная память"
    
    def generate_report(self) -> str:
        """Сгенерировать текстовый отчет"""
        report = []
        report.append("="*80)
        report.append(f"ОТЧЕТ ПО ЭТАПУ 2: ВНЕДРЕНИЕ ШИФРОВАНИЯ")
        report.append(f"Организация: {self.organization}")
        report.append(f"Дата генерации: {datetime.now().strftime('%d.%m.%Y %H:%M')}")
        report.append("="*80)
        
        # 2.1. Криптостандарты
        report.append("\n2.1. ВЫБОР КРИПТОСТАНДАРТОВ")
        report.append("-"*40)
        
        for rec in self.recommendations["crypto_standards"]:
            report.append(f"\nУстройство ID: {rec['device_id']} - {rec['device']}")
            report.append(f"Текущее шифрование: {rec['current_encryption']}")
            report.append(f"Приоритет: {rec['priority'].upper()}")
            for action in rec["actions"]:
                report.append(f"  • {action}")
        
        # 2.2. Защищенные каналы
        report.append("\n\n2.2. НАСТРОЙКА ЗАЩИЩЕННЫХ КАНАЛОВ")
        report.append("-"*40)
        
        for rec in self.recommendations["secure_channels"]:
            report.append(f"\nГруппа: {rec['group']}")
            report.append(f"Устройства: {', '.join(rec['devices'])}")
            report.append(f"Протоколы: {', '.join(rec['protocols'])}")
            if rec['gateway']:
                report.append(f"Шлюз: {rec['gateway']}")
            for action in rec["recommendations"]:
                report.append(f"  • {action}")
        
        # 2.3. Управление ключами
        report.append("\n\n2.3. СИСТЕМА УПРАВЛЕНИЯ КЛЮЧАМИ")
        report.append("-"*40)
        
        for rec in self.recommendations["key_management"]:
            report.append(f"\nHSM устройство: {rec['hsm_device']}")
            report.append(f"Тип: {rec['type']}")
            for action in rec["recommendations"]:
                report.append(f"  • {action}")
        
        # 2.4. Шифрование хранилищ
        report.append("\n\n2.4. ШИФРОВАНИЕ ХРАНИЛИЩ")
        report.append("-"*40)
        
        for rec in self.recommendations["storage_encryption"]:
            report.append(f"\nУстройство ID: {rec['device_id']} - {rec['device']}")
            report.append(f"Тип хранилища: {rec['storage_type']}")
            for action in rec["recommendations"]:
                report.append(f"  • {action}")
        
        # Новые устройства для добавления
        if self.recommendations["new_devices_to_add"]:
            report.append("\n\nРЕКОМЕНДУЕМЫЕ ДОПОЛНИТЕЛЬНЫЕ УСТРОЙСТВА")
            report.append("-"*40)
            
            for device in self.recommendations["new_devices_to_add"]:
                report.append(f"\n• {device['type']}: {device['manufacturer']} {device['model']}")
                report.append(f"  Назначение: {device['purpose']}")
                report.append(f"  Конфигурация: {device['config']}")
        
        # Требования нормативных документов
        report.append("\n\nНОРМАТИВНЫЕ ТРЕБОВАНИЯ")
        report.append("-"*40)
        report.append("• ФСТЭК Приказ №239: защита информации при передаче по сетям связи")
        report.append("• ГОСТ Р 57580.1-2017: требования к шифрованию для систем КИИ")
        report.append("• ФЗ-152: защита персональных данных")
        report.append("• Приказ ФСБ №378: использование ГОСТ алгоритмов")
        
        return "\n".join(report)
    
    def save_report_to_file(self, filename: str = "encryption_report.txt"):
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
        """Вывести краткое содержание рекомендаций"""
        print("\n" + "="*60)
        print("КРАТКОЕ СОДЕРЖАНИЕ РЕКОМЕНДАЦИЙ")
        print("="*60)
        
        # Статистика
        total_devices = len(self.devices)
        no_encryption = sum(1 for d in self.devices if not d.get("encryption", False))
        needs_replacement = sum(1 for d in self.devices 
                              if d.get("encryption_recommendation", {}).get("replacement_needed", False))
        
        print(f"\n Статистика:")
        print(f"  Всего устройств: {total_devices}")
        print(f"  Без шифрования: {no_encryption}")
        print(f"  Требуют замены: {needs_replacement}")
        
        # Критические рекомендации
        print(f"\n Критические рекомендации:")
        
        for rec in self.recommendations["crypto_standards"]:
            if rec["priority"] == "критический":
                print(f"  • {rec['device']}: {rec['actions'][0][:80]}...")
        
        # Новые устройства
        if self.recommendations["new_devices_to_add"]:
            print(f"\n Рекомендованные к приобритению устройства:")
            for device in self.recommendations["new_devices_to_add"]:
                print(f"  • {device['manufacturer']} {device['model']} - {device['purpose']}")