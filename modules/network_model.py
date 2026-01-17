"""
Модель сети для анализа и сегментации
"""

from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum


class SecurityLevel(Enum):
    """Уровни безопасности сегментов"""
    KII_CRITICAL = "КИИ_КРИТИЧЕСКИЙ"      # КИИ 1-2 категории
    KII_HIGH = "КИИ_ВЫСОКИЙ"             # КИИ 3-4 категории
    INDUSTRIAL = "ПРОМЫШЛЕННЫЙ"          # Оборудование ОТ
    CORPORATE = "КОРПОРАТИВНЫЙ"          # Корпоративная сеть
    IOT_TRUSTED = "IOT_ДОВЕРЕННЫЙ"       # IoT с шифрованием
    IOT_UNTRUSTED = "IOT_НЕДОВЕРЕННЫЙ"   # IoT без шифрования
    PHYSICAL_ACCESS = "ФИЗИЧЕСКИЙ_ДОСТУП" # Устройства с физическим доступом
    GUEST = "ГОСТЕВОЙ"                   # Гостевой доступ
    DMZ = "DMZ"                          # Демилитаризованная зона
    MANAGEMENT = "УПРАВЛЕНИЕ"            # Управление и мониторинг


class ProtocolType(Enum):
    """Типы протоколов для анализа"""
    MANAGEMENT = "Управление"       # SSH, HTTPS, SNMP
    DATA = "Данные"                 # HTTP, MQTT, Modbus
    STREAMING = "Потоковые данные"  # RTSP, RTP
    FILE_TRANSFER = "Передача файлов" # FTP, SMB
    INDUSTRIAL = "Промышленные"     # PROFINET, Modbus, OPC UA


@dataclass
class NetworkConnection:
    """Сетевое соединение между устройствами"""
    source_id: int
    destination_id: int
    protocols: List[str]
    ports: List[int]
    frequency: str = "постоянно"  # постоянно/периодически/редко
    data_volume: str = "средняя"  # низкая/средняя/высокая
    is_required: bool = True      # Необходимо для работы
    description: str = ""


@dataclass
class NetworkSegment:
    """Сегмент сети"""
    id: str
    name: str
    security_level: SecurityLevel
    description: str
    device_ids: List[int] = field(default_factory=list)
    subnet: str = ""              # Например, 192.168.10.0/24
    vlan_id: Optional[int] = None
    firewall_policy: str = "deny_all"  # deny_all, restricted, open
    physical_isolation: bool = False   # Физическая изоляция


@dataclass
class NetworkTopology:
    """Топология сети"""
    segments: List[NetworkSegment] = field(default_factory=list)
    connections: List[NetworkConnection] = field(default_factory=list)
    network_equipment: List[Dict] = field(default_factory=list)
    current_vlans: Dict[int, str] = field(default_factory=dict)  # vlan_id: описание


class NetworkAnalyzer:
    """Анализатор сетевой инфраструктуры"""
    
    def __init__(self, infrastructure: Dict):
        self.infrastructure = infrastructure
        self.devices = infrastructure.get("devices", [])
        self.topology = NetworkTopology()
        self._analyze_current_state()
    
    def _analyze_current_state(self):
        """Проанализировать текущее состояние сети"""
        # Собираем информацию о текущих соединениях (предполагаем, что все общаются со всем)
        # В реальности это должно быть получено из сетевых логов или конфигураций
        
        # Создаем начальные сегменты на основе групп взаимодействия
        self._create_initial_segments()
        
        # Анализируем связи между устройствами
        self._analyze_device_connections()
        
        # Определяем сетевое оборудование
        self._identify_network_equipment()
    
    def _create_initial_segments(self):
        """Создать начальные сегменты на основе характеристик устройств"""
        # 1. КИИ устройства
        kii_critical_devices = [d for d in self.devices if d.get("kii_category", 0) in [1, 2]]
        if kii_critical_devices:
            self.topology.segments.append(NetworkSegment(
                id="segment_kii_critical",
                name="КИИ_КРИТИЧЕСКИЕ",
                security_level=SecurityLevel.KII_CRITICAL,
                description="Устройства КИИ 1-2 категории",
                device_ids=[d["id"] for d in kii_critical_devices],
                subnet="10.10.10.0/24",
                vlan_id=10,
                firewall_policy="deny_all",
                physical_isolation=True
            ))
        
        # 2. Промышленные устройства
        industrial_categories = ["Промышленность (ОТ)", "Энергетика"]
        industrial_devices = [d for d in self.devices 
                            if d.get("category") in industrial_categories]
        if industrial_devices:
            self.topology.segments.append(NetworkSegment(
                id="segment_industrial",
                name="ПРОМЫШЛЕННЫЕ_СИСТЕМЫ",
                security_level=SecurityLevel.INDUSTRIAL,
                description="Промышленное оборудование и ОТ системы",
                device_ids=[d["id"] for d in industrial_devices],
                subnet="10.10.20.0/24",
                vlan_id=20,
                firewall_policy="restricted",
                physical_isolation=True
            ))
        
        # 3. Устройства с физическим доступом
        physical_access_devices = [d for d in self.devices if d.get("physical_access", False)]
        if physical_access_devices:
            self.topology.segments.append(NetworkSegment(
                id="segment_physical_access",
                name="ФИЗИЧЕСКИЙ_ДОСТУП",
                security_level=SecurityLevel.PHYSICAL_ACCESS,
                description="Устройства с возможностью физического доступа",
                device_ids=[d["id"] for d in physical_access_devices],
                subnet="10.10.30.0/24",
                vlan_id=30,
                firewall_policy="deny_all",
                physical_isolation=False  # Но нужен контроль доступа
            ))
        
        # 4. IoT с шифрованием
        encrypted_iot = [d for d in self.devices 
                        if d.get("encryption", False) 
                        and d.get("category") not in industrial_categories]
        if encrypted_iot:
            self.topology.segments.append(NetworkSegment(
                id="segment_iot_trusted",
                name="IOT_ДОВЕРЕННЫЕ",
                security_level=SecurityLevel.IOT_TRUSTED,
                description="IoT устройства с шифрованием",
                device_ids=[d["id"] for d in encrypted_iot],
                subnet="10.10.40.0/24",
                vlan_id=40,
                firewall_policy="restricted"
            ))
        
        # 5. IoT без шифрования
        unencrypted_iot = [d for d in self.devices 
                          if not d.get("encryption", False)
                          and d.get("category") not in industrial_categories]
        if unencrypted_iot:
            self.topology.segments.append(NetworkSegment(
                id="segment_iot_untrusted",
                name="IOT_НЕДОВЕРЕННЫЕ",
                security_level=SecurityLevel.IOT_UNTRUSTED,
                description="IoT устройства без шифрования",
                device_ids=[d["id"] for d in unencrypted_iot],
                subnet="10.10.50.0/24",
                vlan_id=50,
                firewall_policy="deny_all"
            ))
        
        # 6. Корпоративная сеть (предполагаем, что есть серверы/ПК)
        self.topology.segments.append(NetworkSegment(
            id="segment_corporate",
            name="КОРПОРАТИВНАЯ_СЕТЬ",
            security_level=SecurityLevel.CORPORATE,
            description="Корпоративные серверы и рабочие станции",
            device_ids=[],  # Будут добавлены вручную
            subnet="10.10.60.0/24",
            vlan_id=60,
            firewall_policy="restricted"
        ))
        
        # 7. Управление и мониторинг
        self.topology.segments.append(NetworkSegment(
            id="segment_management",
            name="УПРАВЛЕНИЕ_И_МОНИТОРИНГ",
            security_level=SecurityLevel.MANAGEMENT,
            description="Системы управления и мониторинга",
            device_ids=[],  # Будут добавлены вручную
            subnet="10.10.70.0/24",
            vlan_id=70,
            firewall_policy="restricted"
        ))
    
    def _analyze_device_connections(self):
        """Проанализировать соединения между устройствами"""
        # Это упрощенный анализ. В реальности нужно анализировать логи сети.
        
        # Для каждого устройства определяем, с какими другими устройствами оно должно общаться
        for device in self.devices:
            device_id = device["id"]
            device_type = device.get("type", "")
            interaction_group = device.get("interaction_group", "")
            
            # Определяем типичные соединения на основе типа устройства
            if "камера" in device_type.lower():
                # Камеры обычно отправляют видео на NVR/сервер
                for other in self.devices:
                    if "регистратор" in other.get("type", "").lower():
                        self.topology.connections.append(NetworkConnection(
                            source_id=device_id,
                            destination_id=other["id"],
                            protocols=["RTSP", "HTTP"],
                            ports=[554, 80],
                            frequency="постоянно",
                            data_volume="высокая",
                            is_required=True,
                            description="Передача видео с камеры на регистратор"
                        ))
            
            elif "датчик" in device_type.lower():
                # Датчики отправляют данные на шлюз/сервер
                for other in self.devices:
                    if "маршрутизатор" in other.get("type", "").lower() or "шлюз" in other.get("type", "").lower():
                        self.topology.connections.append(NetworkConnection(
                            source_id=device_id,
                            destination_id=other["id"],
                            protocols=["MQTT", "HTTP"],
                            ports=[1883, 80],
                            frequency="периодически",
                            data_volume="низкая",
                            is_required=True,
                            description="Передача данных с датчика на шлюз"
                        ))
            
            elif "маршрутизатор" in device_type.lower() or "коммутатор" in device_type.lower():
                # Сетевое оборудование общается со всеми устройствами в своем сегменте
                pass  # Управление через SSH/HTTPS будет добавлено отдельно
    
    def _identify_network_equipment(self):
        """Определить сетевое оборудование"""
        network_devices = []
        
        for device in self.devices:
            device_type = device.get("type", "").lower()
            if any(keyword in device_type for keyword in ["маршрутизатор", "коммутатор", "межсетевой", "фаервол", "шлюз"]):
                network_devices.append({
                    "id": device["id"],
                    "type": device["type"],
                    "manufacturer": device["manufacturer"],
                    "model": device["model"],
                    "ip": device.get("ip", "не указан"),
                    "capabilities": self._get_network_capabilities(device)
                })
        
        self.topology.network_equipment = network_devices
    
    def _get_network_capabilities(self, device: Dict) -> List[str]:
        """Определить возможности сетевого оборудования"""
        capabilities = []
        manufacturer = device.get("manufacturer", "").lower()
        model = device.get("model", "").lower()
        
        # Проверяем поддержку VLAN
        if any(brand in manufacturer for brand in ["cisco", "mikrotik", "hp", "hpe", "d-link", "tp-link"]):
            capabilities.append("VLAN")
        
        # Проверяем поддержку QoS
        if any(brand in manufacturer for brand in ["cisco", "mikrotik"]):
            capabilities.append("QoS")
        
        # Проверяем поддержку ACL/Firewall
        if any(brand in manufacturer for brand in ["cisco", "mikrotik", "fortinet", "pfsense"]):
            capabilities.append("Firewall/ACL")
        
        # Проверяем поддержку VPN
        if any(brand in manufacturer for brand in ["cisco", "mikrotik", "fortinet"]):
            capabilities.append("VPN")
        
        return capabilities
    
    def find_device_segment(self, device_id: int) -> Optional[NetworkSegment]:
        """Найти сегмент, к которому принадлежит устройство"""
        for segment in self.topology.segments:
            if device_id in segment.device_ids:
                return segment
        return None
    
    def get_segment_devices(self, segment_id: str) -> List[Dict]:
        """Получить устройства в сегменте"""
        segment = next((s for s in self.topology.segments if s.id == segment_id), None)
        if not segment:
            return []
        
        return [d for d in self.devices if d["id"] in segment.device_ids]
    
    def analyze_security_risks(self) -> List[Dict]:
        """Проанализировать риски безопасности в текущей топологии"""
        risks = []
        
        # 1. Проверяем устройства без шифрования в критических сегментах
        for segment in self.topology.segments:
            if segment.security_level in [SecurityLevel.KII_CRITICAL, SecurityLevel.KII_HIGH]:
                devices = self.get_segment_devices(segment.id)
                for device in devices:
                    if not device.get("encryption", False):
                        risks.append({
                            "type": "КРИТИЧЕСКИЙ",
                            "description": f"Устройство {device['manufacturer']} {device['model']} "
                                          f"без шифрования в сегменте {segment.name}",
                            "recommendation": "Переместить в сегмент IOT_НЕДОВЕРЕННЫЕ или внедрить шифрование",
                            "segment": segment.name
                        })
        
        # 2. Проверяем избыточные соединения
        required_connections = [c for c in self.topology.connections if c.is_required]
        # В реальности здесь должен быть анализ фактических соединений
        
        # 3. Проверяем устройства с физическим доступом
        physical_segment = next((s for s in self.topology.segments 
                               if s.security_level == SecurityLevel.PHYSICAL_ACCESS), None)
        if physical_segment:
            devices = self.get_segment_devices(physical_segment.id)
            for device in devices:
                if device.get("critical", False):
                    risks.append({
                        "type": "ВЫСОКИЙ",
                        "description": f"Критическое устройство {device['manufacturer']} {device['model']} "
                                      f"с физическим доступом",
                        "recommendation": "Усилить физическую защиту или переместить в защищенное помещение",
                        "segment": physical_segment.name
                    })
        
        return risks