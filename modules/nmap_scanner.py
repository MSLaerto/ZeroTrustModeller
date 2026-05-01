#!/usr/bin/env python3
# nmap_scanner.py – модуль автоматизированного сбора данных через nmap

import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

# Параметры сканирования
NMAP_ARGS = "-sS -sV -O -p- --open --max-retries 1 --host-timeout 30m"
OUTPUT_DIR = "data"
OUTPUT_FILE = f"{OUTPUT_DIR}/infrastructure.json"

def run_nmap_scan(ip_range: str) -> str:
    """Запускает nmap, возвращает путь к XML-файлу."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    xml_file = f"/tmp/nmap_scan_{timestamp}.xml"
    cmd = f"nmap {NMAP_ARGS} -oX {xml_file} {ip_range}"
    print(f"Запуск: {cmd}")
    try:
        subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        return xml_file
    except subprocess.CalledProcessError as e:
        print(f"Ошибка nmap: {e.stderr}")
        sys.exit(1)

def parse_nmap_xml(xml_file: str) -> List[Dict[str, Any]]:
    """Парсит XML nmap в список устройств."""
    tree = ET.parse(xml_file)
    root = tree.getroot()
    devices = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        addr = host.find("address")
        if addr is None:
            continue
        ip = addr.get("addr", "")

        # ОС (если определена)
        os_elem = host.find("os/osmatch")
        os_name = os_elem.get("name", "Unknown") if os_elem is not None else "Unknown"

        ports = []
        protocols = set()
        for port in host.findall("ports/port"):
            port_id = port.get("portid")
            state = port.find("state")
            if state is not None and state.get("state") == "open":
                ports.append(int(port_id))
                service = port.find("service")
                if service is not None:
                    proto_name = service.get("name", "").upper()
                    if proto_name:
                        protocols.add(proto_name)

        # Определение типа устройства
        device_type = "Другое"
        if any(p in protocols for p in ["RTSP", "ONVIF", "RTP"]):
            device_type = "IP-камера"
        elif any(p in protocols for p in ["HTTP", "HTTPS", "SNMP"]):
            if "router" in os_name.lower() or any(p in protocols for p in ["SSH"]):
                device_type = "Маршрутизатор"
            else:
                device_type = "Сетевое устройство"
        elif any(p in protocols for p in ["MQTT", "MQTTS"]):
            device_type = "Датчик IoT"
        elif "printer" in os_name.lower():
            device_type = "Принтер"

        encryption = any(p in protocols for p in ["HTTPS", "SSH", "MQTTS", "RTSPS"])
        category = "Сетевое оборудование"
        if device_type == "IP-камера":
            category = "Безопасность"
        elif device_type == "Датчик IoT":
            category = "Датчики и сенсоры"

        device = {
            "id": 0,  # временно, будет пересчитан
            "type": device_type,
            "category": category,
            "manufacturer": "Неизвестен",
            "model": "Unknown",
            "ip": ip,
            "ports": ports,
            "protocols": list(protocols),
            "encryption": encryption,
            "kii_category": 0,
            "uses_domestic_algorithm": False,
            "can_change_protocols": "неизвестно",
            "compute_power": "неизвестно",
            "memory": "неизвестно",
            "data_volume": "неизвестно",
            "interaction_group": "default",
            "physical_access": False,
            "critical": False,
            "added_from_catalog": False,
            "added_at": datetime.now().isoformat(),
            "risk_level": "medium",
        }
        devices.append(device)
    return devices

def merge_with_existing(devices_new: List[Dict], existing_file: str) -> List[Dict]:
    """Объединяет с существующей инфраструктурой, сохраняя ручные правки по IP."""
    if not Path(existing_file).exists():
        return devices_new
    with open(existing_file, 'r', encoding='utf-8') as f:
        existing = json.load(f)
    existing_by_ip = {d["ip"]: d for d in existing.get("devices", []) if "ip" in d}

    for new in devices_new:
        ip = new["ip"]
        if ip in existing_by_ip:
            old = existing_by_ip[ip]
            for key in ["category", "manufacturer", "model", "critical", "kii_category",
                        "physical_access", "interaction_group", "uses_domestic_algorithm",
                        "can_change_protocols", "compute_power", "memory", "data_volume"]:
                if key in old:
                    new[key] = old[key]
    return devices_new

def save_infrastructure(devices: List[Dict], output_file: str, organization: str):
    """Сохраняет инфраструктуру в формате прототипа."""
    for idx, dev in enumerate(devices, 1):
        dev["id"] = idx
    infrastructure = {
        "organization": organization,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "devices": devices,
        "network_info": {"has_vlan": False, "firewall": "Неизвестно",
                         "mfa_solution": "отсутствует", "monitoring_system": "отсутствует"}
    }
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(infrastructure, f, ensure_ascii=False, indent=2)
    print(f"Сохранено в {output_file}, устройств: {len(devices)}")

def main():
    if len(sys.argv) < 2:
        print("Использование: python nmap_scanner.py <IP-диапазон> [--merge]")
        sys.exit(1)
    ip_range = sys.argv[1]
    merge = "--merge" in sys.argv

    print(f"Сканирование {ip_range}...")
    xml_file = run_nmap_scan(ip_range)
    devices = parse_nmap_xml(xml_file)
    if merge:
        devices = merge_with_existing(devices, OUTPUT_FILE)
    save_infrastructure(devices, OUTPUT_FILE, f"Автосканирование {ip_range}")
    Path(xml_file).unlink(missing_ok=True)

if __name__ == "__main__":
    main()