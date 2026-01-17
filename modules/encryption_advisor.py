"""
Модуль для анализа устройств и выдачи рекомендаций по шифрованию
на основе блок-схемы выбора алгоритмов
"""

def analyze_device_for_encryption(device_data):
    """
    Анализирует устройство и выдает рекомендации по алгоритму шифрования
    на основе блок-схемы выбора
    
    device_data: dict с данными устройства
    Возвращает: dict с рекомендациями
    """
    # Извлекаем данные из устройства
    kii_category = device_data.get("kii_category", 0)  # 0 - не КИИ, 1-2 - КИИ 1-2 категории
    has_encryption = device_data.get("encryption", False)
    uses_domestic_algo = device_data.get("uses_domestic_algorithm", False)
    data_volume = device_data.get("data_volume", "неизвестно")
    memory = device_data.get("memory", "неизвестно")
    compute_power = device_data.get("compute_power", "неизвестно")
    
    # Преобразуем качественные характеристики в количественные для анализа
    data_volume_kbps = _convert_data_volume_to_kbps(data_volume)
    memory_kb = _convert_memory_to_kb(memory)
    cpu_mhz = _convert_compute_power_to_mhz(compute_power)
    
    # Логика из блок-схемы
    recommendation = {
        "recommended_algorithm": None,
        "replacement_needed": False,
        "reason": "",
        "details": {}
    }
    
    # 1. Проверка КИИ 1-2 категории
    if kii_category in [1, 2]:
        recommendation["recommended_algorithm"] = "Кузнечик/Магма"
        recommendation["reason"] = "Устройство КИИ 1-2 категории требует отечественных алгоритмов"
        recommendation["details"]["kii_check"] = "КИИ 1-2 категории"
        return recommendation
    
    # 2. Проверка наличия шифрования
    if has_encryption:
        if uses_domestic_algo:
            recommendation["recommended_algorithm"] = "Уже используется отечественный алгоритм"
            recommendation["reason"] = "Устройство уже использует отечественный алгоритм шифрования"
            recommendation["details"]["encryption_check"] = "Использует отечественный алгоритм"
            return recommendation
        else:
            # Переходим к проверке объема данных
            pass
    
    # 3. Проверка объема передаваемых данных
    if data_volume_kbps > 10000:  # > 10 Кб/с
        # Ветка: объем > 10 Кб/с
        if memory_kb < 2000:  # < 2 Кб
            if cpu_mhz < 20:  # < 20 МГц
                recommendation["recommended_algorithm"] = "Магма"
                recommendation["reason"] = "Память < 2 Кб, CPU < 20 МГц"
            else:
                recommendation["recommended_algorithm"] = "Present80"
                recommendation["replacement_needed"] = True
                recommendation["reason"] = "Память < 2 Кб, CPU >= 20 МГц - требуется замена устройства"
        elif memory_kb < 4000:  # < 4 Кб
            if cpu_mhz < 50:  # < 50 МГц
                recommendation["recommended_algorithm"] = "ChaCha20"
                recommendation["replacement_needed"] = True
                recommendation["reason"] = "Память < 4 Кб, CPU < 50 МГц - рекомендуется замена"
            else:
                recommendation["recommended_algorithm"] = "Кузнечик"
                recommendation["reason"] = "Память < 4 Кб, CPU >= 50 МГц"
        else:  # память >= 4 Кб
            if cpu_mhz < 100:  # < 100 МГц
                recommendation["recommended_algorithm"] = "Кузнечик"
                recommendation["reason"] = "Память >= 4 Кб, CPU < 100 МГц"
            else:
                recommendation["recommended_algorithm"] = "Магма"
                recommendation["reason"] = "Память >= 4 Кб, CPU >= 100 МГц"
    
    elif data_volume_kbps > 1000:  # > 1 Кб/с и <= 10 Кб/с
        # Ветка: объем > 1 Кб/с
        if memory_kb < 1000:  # < 1 Кб
            if cpu_mhz < 20:  # < 20 МГц
                recommendation["recommended_algorithm"] = "Магма"
                recommendation["reason"] = "Память < 1 Кб, CPU < 20 МГц"
            else:
                recommendation["recommended_algorithm"] = "Present80"
                recommendation["replacement_needed"] = True
                recommendation["reason"] = "Память < 1 Кб, CPU >= 20 МГц - требуется замена устройства"
        else:  # память >= 1 Кб
            recommendation["recommended_algorithm"] = "Кузнечик"
            recommendation["reason"] = "Объем данных > 1 Кб/с, память >= 1 Кб"
    
    else:  # <= 1 Кб/с
        # Мало данных, выбираем по характеристикам
        if memory_kb < 1000 and cpu_mhz < 20:
            recommendation["recommended_algorithm"] = "Магма"
            recommendation["reason"] = "Мало данных, память < 1 Кб, CPU < 20 МГц"
        elif memory_kb < 1000 and cpu_mhz >= 20:
            recommendation["recommended_algorithm"] = "Present80"
            recommendation["replacement_needed"] = True
            recommendation["reason"] = "Мало данных, память < 1 Кб, CPU >= 20 МГц - требуется замена"
        else:
            recommendation["recommended_algorithm"] = "Кузнечик"
            recommendation["reason"] = "Мало данных, но достаточные ресурсы для отечественных алгоритмов"
    
    # Если что-то пошло не так
    if not recommendation["recommended_algorithm"]:
        recommendation["recommended_algorithm"] = "Кузнечик (по умолчанию)"
        recommendation["reason"] = "Не удалось определить оптимальный алгоритм, выбран по умолчанию"
    
    return recommendation


def _convert_data_volume_to_kbps(data_volume):
    """Преобразует качественную характеристику объема данных в Кб/с"""
    mapping = {
        "высокая": 15000,  # 15 Кб/с
        "средняя": 5000,   # 5 Кб/с
        "низкая": 500,     # 0.5 Кб/с
        "неизвестно": 1000 # по умолчанию 1 Кб/с
    }
    return mapping.get(data_volume, 1000)


def _convert_memory_to_kb(memory):
    """Преобразует качественную характеристику памяти в Кб"""
    mapping = {
        "высокая": 8000,   # 8 Мб = 8192 Кб
        "средняя": 2048,   # 2 Мб = 2048 Кб
        "низкая": 256,     # 256 Кб
        "неизвестно": 1024 # по умолчанию 1 Мб = 1024 Кб
    }
    return mapping.get(memory, 1024)


def _convert_compute_power_to_mhz(compute_power):
    """Преобразует качественную характеристику процессора в МГц"""
    mapping = {
        "высокая": 800,    # 800 МГц
        "средняя": 200,    # 200 МГц
        "низкая": 50,      # 50 МГц
        "неизвестно": 100  # по умолчанию 100 МГц
    }
    return mapping.get(compute_power, 100)