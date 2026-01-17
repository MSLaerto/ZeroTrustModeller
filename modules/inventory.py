"""
Модуль инвентаризации IoT-устройств
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

from modules import enums
from modules.validators import validate_ip, validate_ports
from modules.encryption_advisor import analyze_device_for_encryption

class InventoryManager:
    """Менеджер инвентаризации IoT-устройств"""
    
    def __init__(self):
        self.data_dir = Path("data")
        self.config_dir = Path("config")
        self.infrastructure_file = self.data_dir / "infrastructure.json"
        self.devices_catalog_file = self.config_dir / "devices_catalog.json"
        self.device_types_file = self.config_dir / "device_types.json"
        self.protocols_file = self.config_dir / "protocols.json"
        self.categories_file = self.config_dir / "categories.json"
        
        # Создаем директории, если их нет
        self.data_dir.mkdir(exist_ok=True)
        self.config_dir.mkdir(exist_ok=True)
        
        # Загружаем данные
        self.infrastructure = self._load_infrastructure()
        self.devices_catalog = self._load_json_file(self.devices_catalog_file, {"devices": []})
        self.device_types = self._load_json_file(self.device_types_file, [])
        self.protocols = self._load_json_file(self.protocols_file, [])
        self.categories = self._load_json_file(self.categories_file, [])
        
        # Добавляем "Другое" в списки, если нет
        if "Другое" not in self.device_types:
            self.device_types.append("Другое")
        
        if "Другое" not in self.categories:
            self.categories.append("Другое")
        
        # ID следующего устройства
        self.next_id = max([d["id"] for d in self.infrastructure["devices"]]) + 1 if self.infrastructure["devices"] else 1
    
    def _load_json_file(self, filepath: Path, default):
        """Загрузить JSON файл"""
        if filepath.exists():
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                print(f"Ошибка чтения файла: {filepath.name}")
                return default
        return default
    
    def _load_infrastructure(self) -> Dict:
        """Загрузить инфраструктуру из файла"""
        if self.infrastructure_file.exists():
            try:
                with open(self.infrastructure_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                print("Ошибка чтения файла инфраструктуры")
        
        # Создаем новую инфраструктуру
        return {
            "organization": "",
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "devices": [],
            "network_info": {
                "has_vlan": False,
                "firewall": "",
                "mfa_solution": "отсутствует",
                "monitoring_system": ""
            }
        }
    
    def _save_infrastructure(self):
        """Сохранить инфраструктуру в файл"""
        self.infrastructure["updated_at"] = datetime.now().isoformat()
        
        try:
            with open(self.infrastructure_file, 'w', encoding='utf-8') as f:
                json.dump(self.infrastructure, f, ensure_ascii=False, indent=2)
            print(f"Инфраструктура сохранена в {self.infrastructure_file}")
        except Exception as e:
            print(f"Ошибка сохранения: {e}")
    
    def show_summary(self):
        """Показать сводку по инфраструктуре"""
        devices = self.infrastructure["devices"]
        
        print("\n" + "="*60)
        print("СВОДКА ПО ИНФРАСТРУКТУРЕ")
        print("="*60)
        print(f"Организация: {self.infrastructure.get('organization', 'Не указана')}")
        print(f"Всего устройств: {len(devices)}")
        
        # Группировка по типам
        types = {}
        for device in devices:
            device_type = device.get("type", "Неизвестно")
            types[device_type] = types.get(device_type, 0) + 1
        
        print("\nРаспределение по типам:")
        for device_type, count in types.items():
            print(f"  {device_type}: {count} шт.")
        
        # Критические устройства
        critical = sum(1 for d in devices if d.get("critical", False))
        print(f"Критических устройств: {critical}")
        
        # Устройства с шифрованием
        with_encryption = sum(1 for d in devices if d.get("encryption", False))
        if devices:
            percentage = with_encryption/len(devices)*100
            print(f"С шифрованием: {with_encryption} ({percentage:.1f}%)")
        else:
            print("С шифрованием: 0")
        
        # Группы взаимодействия
        groups = {}
        for device in devices:
            group = device.get("interaction_group", "без группы")
            groups[group] = groups.get(group, 0) + 1
        
        if groups:
            print("\nГруппы взаимодействия:")
            for group, count in groups.items():
                print(f"  {group}: {count} шт.")
        
        print("="*60)
    
    def _select_from_list(self, items: list, prompt: str, allow_custom: bool = False) -> str:
        """Выбрать элемент из списка"""
        if not items:
            if allow_custom:
                return input(f"{prompt}: ").strip()
            return ""
        
        print(f"\n{prompt}:")
        for i, item in enumerate(items, 1):
            print(f"{i}. {item}")
        
        if allow_custom:
            print(f"{len(items) + 1}. Другое (ввести вручную)")
        
        while True:
            try:
                choice = input("Выберите номер: ").strip()
                if not choice:
                    return ""
                
                choice_num = int(choice)
                
                if 1 <= choice_num <= len(items):
                    return items[choice_num - 1]
                elif allow_custom and choice_num == len(items) + 1:
                    custom = input("Введите значение: ").strip()
                    if custom:
                        return custom
                    else:
                        print("Значение не может быть пустым")
                else:
                    print(f"Введите число от 1 до {len(items) + 1 if allow_custom else len(items)}")
            except ValueError:
                print("Введите число")
    
    def _select_multiple_from_list(self, items: list, prompt: str) -> list:
        """Выбрать несколько элементов из списка"""
        if not items:
            return []
        
        print(f"\n{prompt}:")
        for i, item in enumerate(items, 1):
            print(f"{i}. {item}")
        
        print("Введите номера через запятую (например: 1,3,5)")
        print("Или нажмите Enter чтобы выбрать все")
        
        while True:
            choice = input("Выберите номера: ").strip()
            
            if not choice:
                return items.copy()
            
            selected = []
            try:
                for num_str in choice.split(','):
                    num = int(num_str.strip())
                    if 1 <= num <= len(items):
                        selected.append(items[num - 1])
                
                if selected:
                    return selected
                else:
                    print("Выберите хотя бы один элемент")
            except ValueError:
                print("Введите числа через запятую")
    
    def _select_protocols(self) -> list:
        """Выбрать протоколы из списка"""
        print("\nВыбор протоколов:")
        
        # Группируем протоколы по категориям
        protocols_by_category = {}
        for protocol in self.protocols:
            category = protocol.get("category", "без категории")
            if category not in protocols_by_category:
                protocols_by_category[category] = []
            protocols_by_category[category].append(protocol)
        
        selected_protocols = []
        
        # Выводим протоколы по категориям
        for category, protocols in protocols_by_category.items():
            print(f"\n{category.upper()}:")
            for i, protocol in enumerate(protocols, 1):
                name = protocol.get("name", "Неизвестно")
                encryption = "✓" if protocol.get("encryption", False) else "✗"
                description = protocol.get("description", "")
                print(f"{i}. {name} (шифрование: {encryption}) - {description}")
            
            choice = input(f"\nВыберите протоколы из категории '{category}' (номера через запятую, Enter для пропуска): ").strip()
            
            if choice:
                for num_str in choice.split(','):
                    try:
                        num = int(num_str.strip())
                        if 1 <= num <= len(protocols):
                            selected_protocols.append(protocols[num - 1]["name"])
                    except ValueError:
                        pass
        
        return selected_protocols
    
    def add_device_from_catalog(self):
        """Добавить устройство из каталога"""
        if not self.devices_catalog.get("devices"):
            print("Каталог устройств пуст")
            return
        
        # Показываем категории
        categories = set(device["category"] for device in self.devices_catalog["devices"])
        
        selected_category = self._select_from_list(sorted(categories), "Категории устройств")
        if not selected_category:
            return
        
        # Фильтруем устройства по категории
        category_devices = [d for d in self.devices_catalog["devices"] if d["category"] == selected_category]
        
        # Показываем устройства в категории
        print(f"\nУстройства в категории '{selected_category}':")
        for i, device in enumerate(category_devices, 1):
            print(f"{i}. {device['manufacturer']} {device['model']} ({device['type']}) - риск: {device['risk_level']}")
        
        try:
            device_choice = int(input("\nВыберите устройство (номер): "))
            if 1 <= device_choice <= len(category_devices):
                catalog_device = category_devices[device_choice - 1]
            else:
                print("Неверный выбор устройства")
                return
        except ValueError:
            print("Введите число")
            return
        
        # Запрашиваем дополнительные данные
        print(f"\nДобавление устройства: {catalog_device['manufacturer']} {catalog_device['model']}")
        
        # IP-адрес
        while True:
            ip = input(f"IP-адрес устройства [{catalog_device.get('ip', '192.168.1.100')}]: ").strip()
            if not ip:
                ip = "192.168.1.100"
            
            if validate_ip(ip):
                break
            else:
                print("Неверный формат IP-адреса. Пример: 192.168.1.100")
        
        # Порт
        default_ports = catalog_device.get("ports", [])
        ports_str = input(f"Порты (через запятую) [{','.join(map(str, default_ports))}]: ").strip()
        if ports_str:
            ports = validate_ports(ports_str)
        else:
            ports = default_ports
        
        # Протоколы
        default_protocols = catalog_device.get("typical_protocols", [])
        print(f"\nДоступные протоколы: {', '.join(default_protocols)}")
        print("Вы можете выбрать протоколы из каталога или добавить свои")
        
        use_default = input(f"Использовать протоколы по умолчанию? (да/нет) [да]: ").strip().lower()
        if use_default in ["", "да", "y", "yes"]:
            protocols = default_protocols
        else:
            protocols = self._select_protocols()
            if not protocols:
                protocols = default_protocols
        
        # Остальные поля
        encryption = input(f"Использует ли шифрование? (да/нет) [{'да' if catalog_device['typical_encryption'] else 'нет'}]: ").strip().lower() == "да"
        
        can_change_protocols = self._select_from_list(
            enums.CAN_CHANGE_PROTOCOLS_CHOICES,
            "Возможность изменять протоколы",
            allow_custom=False
        ) or catalog_device.get("can_change_protocols", "неизвестно")
        
        # Категория КИИ
        print("\nКатегория КИИ:")
        print("0 - Не является КИИ")
        print("1 - КИИ 1 категории (особо важные объекты)")
        print("2 - КИИ 2 категории")
        print("3 - КИИ 3 категории")
        print("4 - КИИ 4 категории")
        kii_category_input = input("Введите категорию КИИ [0]: ").strip()
        if not kii_category_input:
            kii_category = 0
        else:
            try:
                kii_category = int(kii_category_input)
                if kii_category not in [0, 1, 2, 3, 4]:
                    kii_category = 0
            except ValueError:
                kii_category = 0
        
        # Использует ли уже отечественный алгоритм?
        if encryption:
            uses_domestic = input("Использует ли уже отечественный алгоритм шифрования? (да/нет) [нет]: ").strip().lower() == "да"
        else:
            uses_domestic = False

        compute_power = self._select_from_list(
            enums.COMPUTE_POWER_CHOICES,
            "Вычислительная мощность устройства",
            allow_custom=False
        ) or catalog_device.get("compute_power", "неизвестно")
        
        memory = self._select_from_list(
            enums.MEMORY_CHOICES,
            "Память устройства",
            allow_custom=False
        ) or catalog_device.get("memory", "неизвестно")
        
        data_volume = self._select_from_list(
            enums.DATA_VOLUME_CHOICES,
            "Объем передаваемых данных",
            allow_custom=False
        ) or catalog_device.get("data_volume", "неизвестно")
        
        interaction_group = input(f"Группа взаимодействия [{catalog_device.get('interaction_group', '')}]: ").strip()
        if not interaction_group:
            interaction_group = catalog_device.get("interaction_group", "default_group")
        
        physical_access = input(f"Есть ли физический доступ к устройству? (да/нет) [нет]: ").strip().lower() == "да"
        critical = input(f"Является ли критическим устройством? (да/нет) [нет]: ").strip().lower() == "да"
        
        # Создаем новое устройство
        new_device = {
            "id": self.next_id,
            "type": catalog_device["type"],
            "category": catalog_device["category"],
            "manufacturer": catalog_device["manufacturer"],
            "model": catalog_device["model"],
            "ip": ip,
            "ports": ports,
            "protocols": protocols,
            "encryption": encryption,
            "kii_category": kii_category,
            "uses_domestic_algorithm": uses_domestic,
            "can_change_protocols": can_change_protocols,
            "compute_power": compute_power,
            "memory": memory,
            "data_volume": data_volume,
            "interaction_group": interaction_group,
            "physical_access": physical_access,
            "critical": critical,
            "added_from_catalog": True,
            "catalog_id": catalog_device["id"],
            "risk_level": catalog_device["risk_level"],
            "replacement_suggestion": catalog_device.get("replacement_suggestion"),
            "added_at": datetime.now().isoformat()
        }

        encryption_recommendation = analyze_device_for_encryption(new_device)
        
        # Добавляем рекомендации в устройство
        new_device["encryption_recommendation"] = encryption_recommendation
        
        if encryption_recommendation.get("replacement_needed", False):
            new_device["encryption_replacement"] = {
                "replacement_needed": True,
                "reason": encryption_recommendation.get("reason", ""),
                "priority": "высокий" if new_device.get("critical", False) else "средний"
            }
        else:
            new_device["encryption_replacement"] = {
                "replacement_needed": False,
                "reason": "Устройство поддерживает отечественные алгоритмы",
                "priority": "низкий"
            }

        # Если требуется замена, обновляем replacement_suggestion
        if encryption_recommendation.get("replacement_needed", False):
            if not new_device.get("replacement_suggestion"):
                new_device["replacement_suggestion"] = f"Требуется замена: {encryption_recommendation.get('reason', '')}"
        # ===========================
        
        self.infrastructure["devices"].append(new_device)
        self.next_id += 1
        
        self.infrastructure["devices"].append(new_device)
        self.next_id += 1
        
        print(f"Устройство добавлено (ID: {new_device['id']})")
        self._save_infrastructure()
    
    def add_custom_device(self):
        """Добавить пользовательское устройство"""
        print("\nДобавление пользовательского устройства")
        
        # Выбор категории
        category = self._select_from_list(self.categories, "Категория устройства", allow_custom=True)
        if not category:
            category = "Другое"
        
        # Выбор типа
        device_type = self._select_from_list(self.device_types, "Тип устройства", allow_custom=True)
        if not device_type:
            device_type = "Другое"
        
        # Основная информация
        manufacturer = input("Производитель: ").strip()
        model = input("Модель: ").strip()
        
        # IP-адрес
        while True:
            ip = input("IP-адрес [192.168.1.100]: ").strip() or "192.168.1.100"
            if validate_ip(ip):
                break
            else:
                print("Неверный формат IP-адреса. Пример: 192.168.1.100")
        
        # Порты
        while True:
            ports_str = input("Порты (через запятую, например: 80,443,8080) []: ").strip()
            ports = validate_ports(ports_str)
            if ports_str and not ports:
                print("Неверный формат портов. Пример: 80,443,8080")
                continue
            break
        
        # Протоколы
        protocols = self._select_protocols()
        
        # Остальные поля
        encryption = input("Использует ли шифрование? (да/нет) [нет]: ").strip().lower() == "да"
        
        can_change_protocols = self._select_from_list(
            enums.CAN_CHANGE_PROTOCOLS_CHOICES,
            "Возможность изменять протоколы",
            allow_custom=False
        ) or "неизвестно"
        
        print("\nКатегория КИИ:")
        print("0 - Не является КИИ")
        print("1 - КИИ 1 категории (особо важные объекты)")
        print("2 - КИИ 2 категории")
        print("3 - КИИ 3 категории")
        print("4 - КИИ 4 категории")
        kii_category_input = input("Введите категорию КИИ [0]: ").strip()
        if not kii_category_input:
            kii_category = 0
        else:
            try:
                kii_category = int(kii_category_input)
                if kii_category not in [0, 1, 2, 3, 4]:
                    kii_category = 0
            except ValueError:
                kii_category = 0
        
        # Использует ли уже отечественный алгоритм?
        if encryption:
            uses_domestic = input("Использует ли уже отечественный алгоритм шифрования? (да/нет) [нет]: ").strip().lower() == "да"
        else:
            uses_domestic = False

        compute_power = self._select_from_list(
            enums.COMPUTE_POWER_CHOICES,
            "Вычислительная мощность устройства",
            allow_custom=False
        ) or "неизвестно"
        
        memory = self._select_from_list(
            enums.MEMORY_CHOICES,
            "Память устройства",
            allow_custom=False
        ) or "неизвестно"
        
        data_volume = self._select_from_list(
            enums.DATA_VOLUME_CHOICES,
            "Объем передаваемых данных",
            allow_custom=False
        ) or "неизвестно"
        
        interaction_group = input("Группа взаимодействия [default_group]: ").strip() or "default_group"
        physical_access = input("Есть ли физический доступ к устройству? (да/нет) [нет]: ").strip().lower() == "да"
        critical = input("Является ли критическим устройством? (да/нет) [нет]: ").strip().lower() == "да"
        
        # Создаем устройство
        device = {
            "id": self.next_id,
            "type": device_type,
            "category": category,
            "manufacturer": manufacturer,
            "model": model,
            "ip": ip,
            "ports": ports,
            "protocols": protocols,
            "encryption": encryption,
            "kii_category": kii_category,
            "uses_domestic_algorithm": uses_domestic,
            "can_change_protocols": can_change_protocols,
            "compute_power": compute_power,
            "memory": memory,
            "data_volume": data_volume,
            "interaction_group": interaction_group,
            "physical_access": physical_access,
            "critical": critical,
            "added_from_catalog": False,
            "added_at": datetime.now().isoformat()
        }

        encryption_recommendation = analyze_device_for_encryption(device)
        
        # Добавляем рекомендации в устройство
        device["encryption_recommendation"] = encryption_recommendation
        
        # Если требуется замена, обновляем replacement_suggestion
        if encryption_recommendation.get("replacement_needed", False):
            if not device.get("replacement_suggestion"):
                device["replacement_suggestion"] = f"Требуется замена: {encryption_recommendation.get('reason', '')}"
        
        self.infrastructure["devices"].append(device)
        self.next_id += 1
        
        print(f"Пользовательское устройство добавлено (ID: {device['id']})")
        self._save_infrastructure()
    
    def edit_device(self):
        """Редактировать устройство"""
        if not self.infrastructure["devices"]:
            print("Нет устройств для редактирования")
            return
        
        self.show_devices_list()
        
        try:
            device_id = int(input("\nВведите ID устройства для редактирования: "))
        except ValueError:
            print("ID должен быть числом")
            return
        
        device = next((d for d in self.infrastructure["devices"] if d["id"] == device_id), None)
        if not device:
            print(f"Устройство с ID {device_id} не найдено")
            return
        
        print(f"\nРедактирование устройства ID: {device_id}")
        print(f"Текущие данные: {device['manufacturer']} {device['model']}")
        
        # Редактирование полей
        device["type"] = self._select_from_list(self.device_types, "Тип устройства", allow_custom=True) or device["type"]
        device["category"] = self._select_from_list(self.categories, "Категория", allow_custom=True) or device["category"]
        device["manufacturer"] = input(f"Производитель [{device['manufacturer']}]: ").strip() or device["manufacturer"]
        device["model"] = input(f"Модель [{device['model']}]: ").strip() or device["model"]
        
        # IP-адрес
        while True:
            ip = input(f"IP-адрес [{device.get('ip', '192.168.1.100')}]: ").strip()
            if not ip:
                ip = device.get("ip", "192.168.1.100")
            
            if validate_ip(ip):
                device["ip"] = ip
                break
            else:
                print("Неверный формат IP-адреса. Пример: 192.168.1.100")
        
        # Порты
        current_ports = ','.join(map(str, device.get("ports", [])))
        ports_str = input(f"Порты (через запятую) [{current_ports}]: ").strip()
        if ports_str:
            ports = validate_ports(ports_str)
            if ports:
                device["ports"] = ports
        
        # Протоколы
        print(f"\nТекущие протоколы: {', '.join(device.get('protocols', []))}")
        change_protocols = input("Изменить протоколы? (да/нет) [нет]: ").strip().lower()
        if change_protocols == "да":
            new_protocols = self._select_protocols()
            if new_protocols:
                device["protocols"] = new_protocols
        
        # Остальные поля
        device["encryption"] = input(f"Использует шифрование? (да/нет) [{'да' if device.get('encryption') else 'нет'}]: ").strip().lower() == "да"
        
        current_kii = device.get("kii_category", 0)
        print(f"\nТекущая категория КИИ: {current_kii}")
        print("0 - Не является КИИ")
        print("1 - КИИ 1 категории (особо важные объекты)")
        print("2 - КИИ 2 категории")
        print("3 - КИИ 3 категории")
        print("4 - КИИ 4 категории")
        kii_input = input(f"Новая категория КИИ [{current_kii}]: ").strip()
        if kii_input:
            try:
                kii = int(kii_input)
                if kii in [0, 1, 2, 3, 4]:
                    device["kii_category"] = kii
            except ValueError:
                pass
        
        # Использует ли уже отечественный алгоритм?
        if device.get("encryption", False):
            current_domestic = device.get("uses_domestic_algorithm", False)
            domestic_input = input(f"Использует отечественный алгоритм? (да/нет) [{'да' if current_domestic else 'нет'}]: ").strip().lower()
            if domestic_input:
                device["uses_domestic_algorithm"] = domestic_input == "да"
        else:
            device["uses_domestic_algorithm"] = False

        device["can_change_protocols"] = self._select_from_list(
            enums.CAN_CHANGE_PROTOCOLS_CHOICES,
            "Возможность изменять протоколы",
            allow_custom=False
        ) or device.get("can_change_protocols", "неизвестно")
        
        device["compute_power"] = self._select_from_list(
            enums.COMPUTE_POWER_CHOICES,
            "Вычислительная мощность",
            allow_custom=False
        ) or device.get("compute_power", "неизвестно")
        
        device["memory"] = self._select_from_list(
            enums.MEMORY_CHOICES,
            "Память устройства",
            allow_custom=False
        ) or device.get("memory", "неизвестно")
        
        device["data_volume"] = self._select_from_list(
            enums.DATA_VOLUME_CHOICES,
            "Объем передаваемых данных",
            allow_custom=False
        ) or device.get("data_volume", "неизвестно")
        
        device["interaction_group"] = input(f"Группа взаимодействия [{device.get('interaction_group', '')}]: ").strip() or device.get("interaction_group", "default_group")
        device["physical_access"] = input(f"Есть физический доступ? (да/нет) [{'да' if device.get('physical_access') else 'нет'}]: ").strip().lower() == "да"
        device["critical"] = input(f"Критическое устройство? (да/нет) [{'да' if device.get('critical') else 'нет'}]: ").strip().lower() == "да"
        
        # Обновляем время изменения
        device["updated_at"] = datetime.now().isoformat()
        
        print(f"Устройство ID: {device_id} обновлено")
        self._save_infrastructure()
    
    def delete_device(self):
        """Удалить устройство"""
        if not self.infrastructure["devices"]:
            print("Нет устройств для удаления")
            return
        
        self.show_devices_list()
        
        try:
            device_id = int(input("\nВведите ID устройства для удаления: "))
        except ValueError:
            print("ID должен быть числом")
            return
        
        device = next((d for d in self.infrastructure["devices"] if d["id"] == device_id), None)
        if not device:
            print(f"Устройство с ID {device_id} не найдено")
            return
        
        confirm = input(f"Удалить устройство {device['manufacturer']} {device['model']} (ID: {device_id})? (да/нет): ").strip().lower()
        if confirm == "да":
            self.infrastructure["devices"] = [d for d in self.infrastructure["devices"] if d["id"] != device_id]
            print(f"Устройство ID: {device_id} удалено")
            self._save_infrastructure()
    
    def show_devices_list(self):
        """Показать список всех устройств"""
        devices = self.infrastructure["devices"]
        
        if not devices:
            print("Устройства не добавлены")
            return
        
        print("\n" + "="*100)
        print("СПИСОК УСТРОЙСТВ")
        print("="*100)
        print(f"{'ID':<4} {'Тип':<20} {'Произв.':<12} {'Модель':<15} {'IP':<15} {'Порты':<12} {'Шифр':<5} {'Группа':<15}")
        print("-"*100)
        
        for device in devices:
            device_id = str(device["id"])
            device_type = device.get("type", "-")[:20]
            manufacturer = device.get("manufacturer", "-")[:12]
            model = device.get("model", "-")[:15]
            ip = device.get("ip", "-")[:15]
            ports = ','.join(map(str, device.get("ports", [])))[:12]
            encryption = "✓" if device.get("encryption") else "✗"
            group = device.get("interaction_group", "-")[:15]
            
            print(f"{device_id:<4} {device_type:<20} {manufacturer:<12} {model:<15} {ip:<15} {ports:<12} {encryption:<5} {group:<15}")
        
        print("="*100)
        
        # Дополнительная информация по выбору
        if input("\nПоказать подробную информацию? (да/нет) [нет]: ").strip().lower() == "да":
            for device in devices:
                print(f"\n--- Устройство ID: {device['id']} ---")
                print(f"Тип: {device.get('type')}")
                print(f"Категория: {device.get('category')}")
                print(f"Производитель: {device.get('manufacturer')}")
                print(f"Модель: {device.get('model')}")
                print(f"IP: {device.get('ip')}")
                print(f"Порты: {device.get('ports')}")
                print(f"Протоколы: {', '.join(device.get('protocols', []))}")
                print(f"Шифрование: {'Да' if device.get('encryption') else 'Нет'}")
                print(f"Можно менять протоколы: {device.get('can_change_protocols')}")
                print(f"Выч. мощность: {device.get('compute_power')}")
                print(f"Память: {device.get('memory')}")
                print(f"Объем данных: {device.get('data_volume')}")
                print(f"Группа: {device.get('interaction_group')}")
                print(f"Физ. доступ: {'Да' if device.get('physical_access') else 'Нет'}")
                print(f"Критическое: {'Да' if device.get('critical') else 'Нет'}")
                print(f"Категория КИИ: {device.get('kii_category', 0)}")
                print(f"Использует отеч. алгоритм: {'Да' if device.get('uses_domestic_algorithm') else 'Нет'}")
                if device.get("encryption_recommendation"):
                    rec = device["encryption_recommendation"]
                    print(f"\nРекомендации по шифрованию:")
                    print(f"  Алгоритм: {rec.get('recommended_algorithm', 'не определен')}")
                    print(f"  Требуется замена: {'ДА' if rec.get('replacement_needed') else 'нет'}")
                    print(f"  Причина: {rec.get('reason', '')}")
    
    def set_organization_info(self):
        """Установить информацию об организации"""
        print("\nИнформация об организации")
        
        current = self.infrastructure.get("organization", "")
        if current:
            print(f"Текущее название: {current}")
        
        new_name = input("Введите название организации: ").strip()
        if new_name:
            self.infrastructure["organization"] = new_name
            print(f"Организация установлена: {new_name}")
            self._save_infrastructure()
    
    def analyze_all_devices(self):
        """Проанализировать все устройства и обновить рекомендации"""
        print("\n" + "="*60)
        print("АНАЛИЗ ВСЕХ УСТРОЙСТВ")
        print("="*60)
        
        devices_count = len(self.infrastructure["devices"])
        if devices_count == 0:
            print("Нет устройств для анализа")
            return
        
        print(f"Начинаю анализ {devices_count} устройств...")
        
        analyzed = 0
        need_replacement = 0
        
        for device in self.infrastructure["devices"]:
            # Анализируем устройство
            recommendation = analyze_device_for_encryption(device)
            
            # Обновляем рекомендации
            device["encryption_recommendation"] = recommendation
            
            # Если требуется замена, обновляем replacement_suggestion
            if recommendation.get("replacement_needed", False):
                need_replacement += 1
                if not device.get("replacement_suggestion"):
                    device["replacement_suggestion"] = f"Требуется замена: {recommendation.get('reason', '')}"
            
            analyzed += 1
            if analyzed % 5 == 0:
                print(f"  Проанализировано {analyzed}/{devices_count} устройств...")
        
        print(f"\nАнализ завершен!")
        print(f"Всего устройств: {devices_count}")
        print(f"Требуют замены: {need_replacement}")
        print(f"Рекомендации обновлены")
        print("="*60)
        
        self._save_infrastructure()

    def run(self):
        """Запустить менеджер инвентаризации"""
        print("\n" + "="*50)
        print("ЭТАП 1: ИНВЕНТАРИЗАЦИЯ УСТРОЙСТВ")
        print("="*50)
        
        # Показываем сводку
        self.show_summary()
        
        while True:
            print("\nМЕНЮ ИНВЕНТАРИЗАЦИИ")
            print("1. Добавить устройство из каталога")
            print("2. Добавить пользовательское устройство")
            print("3. Показать список устройств")
            print("4. Редактировать устройство")
            print("5. Удалить устройство")
            print("6. Настроить информацию об организации")
            print("7. Анализировать все устройства (обновить рекомендации)")
            print("8. Сохранить и вернуться в главное меню")
            print("9. Выйти без сохранения")
            
            choice = input("\nВыберите действие: ").strip()
            
            if choice == "1":
                self.add_device_from_catalog()
            elif choice == "2":
                self.add_custom_device()
            elif choice == "3":
                self.show_devices_list()
            elif choice == "4":
                self.edit_device()
            elif choice == "5":
                self.delete_device()
            elif choice == "6":
                self.set_organization_info()
            elif choice == "7":
                self.analyze_all_devices()
            elif choice == "8":
                self._save_infrastructure()
                print("Изменения сохранены")
                break
            elif choice == "9":
                confirm = input("Выйти без сохранения изменений? (да/нет): ").strip().lower()
                if confirm == "да":
                    self.infrastructure = self._load_infrastructure()
                    print("Изменения не сохранены")
                    break

if __name__ == "__main__":
    manager = InventoryManager()
    manager.run()