"""
Валидаторы ввода данных
"""

def validate_ip(ip: str) -> bool:
    """Проверить корректность IP-адреса"""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    
    for part in parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
    
    return True

def validate_port(port: str) -> bool:
    """Проверить корректность порта"""
    try:
        port_num = int(port)
        return 0 <= port_num <= 65535
    except ValueError:
        return False

def validate_ports(ports_str: str) -> list:
    """Проверить и преобразовать строку портов в список"""
    ports = []
    if not ports_str:
        return ports
    
    for port in ports_str.split(','):
        port = port.strip()
        if validate_port(port):
            ports.append(int(port))
    
    return ports