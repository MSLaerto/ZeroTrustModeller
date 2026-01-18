"""
modules/report_system.py
Унифицированная система генерации отчетов по всем этапам
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from modules.encryption_planner import EncryptionPlanner
from modules.segmentation_planner import SegmentationPlanner
from modules.zti_calculator import ZTICalculator

class ReportSystem:
    """Унифицированная система генерации отчетов по всем этапам"""
    
    def __init__(self, infrastructure: Dict):
        self.infrastructure = infrastructure
        self.devices = infrastructure.get("devices", [])
        self.organization = infrastructure.get("organization", "Неизвестная организация")
        self.created_at = infrastructure.get("created_at", datetime.now().isoformat())
        self.updated_at = infrastructure.get("updated_at", datetime.now().isoformat())
        
        # Инициализируем планировщики
        self.encryption_planner = EncryptionPlanner(infrastructure)
        self.segmentation_planner = SegmentationPlanner(infrastructure)
        
        # Анализируем инфраструктуру (ленивая инициализация)
        self._encryption_recommendations = None
        self._segmentation_recommendations = None
    
    def calculate_zti_analysis(self) -> Dict:
        """Рассчитать анализ RZT для всех этапов"""
        # Исходный RZT
        initial_zti = ZTICalculator.calculate_initial_zti(self.devices)
        
        # RZT по этапам
        stage_zti_list = []
        
        # Этап 2: Шифрование
        encryption_zti = ZTICalculator.calculate_stage_zti(
            self.devices, 
            "encryption",
            {"encryption_improvement": 40}
        )
        stage_zti_list.append(encryption_zti)
        
        # Этап 3: Сегментация
        segmentation_zti = ZTICalculator.calculate_stage_zti(
            self.devices,
            "segmentation",
            {"segmentation_level": 70, "import_reduction": 20}
        )
        stage_zti_list.append(segmentation_zti)
        
        # Этап 4: MFA
        mfa_zti = ZTICalculator.calculate_stage_zti(
            self.devices,
            "mfa",
            {"mfa_coverage": 80, "import_reduction": 10}
        )
        stage_zti_list.append(mfa_zti)
        
        # Этап 5: Мониторинг
        monitoring_zti = ZTICalculator.calculate_stage_zti(
            self.devices,
            "monitoring",
            {"overall_improvement": 15}
        )
        stage_zti_list.append(monitoring_zti)
        
        # Итоговый RZT
        final_zti = ZTICalculator.calculate_final_zti(self.devices)
        
        return {
            "initial": initial_zti,
            "stages": stage_zti_list,
            "final": final_zti
        }

    def get_encryption_recommendations(self):
        """Получить рекомендации по шифрованию (ленивая загрузка)"""
        if self._encryption_recommendations is None:
            self._encryption_recommendations = self.encryption_planner.analyze_infrastructure()
        return self._encryption_recommendations
    
    def get_segmentation_recommendations(self):
        """Получить рекомендации по сегментации (ленивая загрузка)"""
        if self._segmentation_recommendations is None:
            self._segmentation_recommendations = self.segmentation_planner.analyze_infrastructure()
        return self._segmentation_recommendations
    
    
    def generate_stage1_report(self) -> str:
        """Сгенерировать отчет по этапу 1 (Инвентаризация)"""
        report = []
        report.append("="*80)
        report.append(f"Отчет по этапу 1: инвентаризация устройств")
        report.append("="*80)
        
        # Основная информация
        report.append(f"\nОсновная информация")
        report.append(f"  Организация: {self.organization}")
        report.append(f"  Дата генерации: {datetime.now().strftime('%d.%m.%Y %H:%M')}")
        report.append(f"  Всего устройств: {len(self.devices)}")
        
        # Статистика
        report.append(f"\nСтатистика устройств")
        
        critical_count = sum(1 for d in self.devices if d.get("critical", False))
        kii_count = sum(1 for d in self.devices if d.get("kii_category", 0) in [1, 2])
        encrypted_count = sum(1 for d in self.devices if d.get("encryption", False))
        physical_access_count = sum(1 for d in self.devices if d.get("physical_access", False))
        
        report.append(f"  • Критических устройств: {critical_count}")
        report.append(f"  • Устройств КИИ 1-2 категории: {kii_count}")
        report.append(f"  • Устройств с шифрованием: {encrypted_count} ({encrypted_count/len(self.devices)*100:.1f}%)")
        report.append(f"  • Устройств с физическим доступом: {physical_access_count}")
        
        # Группировка по категориям
        report.append(f"\nГруппировка по категориям")
        categories = {}
        for device in self.devices:
            cat = device.get("category", "Без категории")
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(device)
        
        for category, devices in categories.items():
            encrypted = sum(1 for d in devices if d.get("encryption", False))
            critical = sum(1 for d in devices if d.get("critical", False))
            report.append(f"  • {category}: {len(devices)} устройств")
            report.append(f"    - С шифрованием: {encrypted}")
            report.append(f"    - Критических: {critical}")
        
        # Устройства, требующие замены
        report.append(f"\nУстройства, требующие внимания")
        
        # 1. Критические устройства без шифрования
        critical_no_enc = [d for d in self.devices 
                          if d.get("critical", False) and not d.get("encryption", False)]
        if critical_no_enc:
            report.append(f"\n  Критические устройства без шифрования:")
            for device in critical_no_enc[:5]:  # Показываем первые 5
                report.append(f"    • {device.get('manufacturer')} {device.get('model')} (ID: {device.get('id')})")
        
        # 2. Устройства КИИ
        kii_devices = [d for d in self.devices if d.get("kii_category", 0) in [1, 2]]
        if kii_devices:
            report.append(f"\n  Устройства кии 1-2 категории:")
            for device in kii_devices[:5]:
                report.append(f"    • {device.get('manufacturer')} {device.get('model')} - категория: {device.get('kii_category')}")
        
        # 3. Устройства с физическим доступом
        physical_devices = [d for d in self.devices if d.get("physical_access", False)]
        if physical_devices:
            report.append(f"\n  Устройства с физическим доступом:")
            for device in physical_devices[:5]:
                report.append(f"    • {device.get('manufacturer')} {device.get('model')} - {device.get('type')}")
        
        # Рекомендации по этапу 1
        report.append(f"\n" + "-"*60)
        report.append("Рекомендации по этапу 1")
        report.append("-"*60)
        
        recommendations = [
            "1. Создать централизованный реестр устройств:",
            "   • Внести все устройства в базу данных с полной информацией",
            "   • Назначить ответственных за каждое устройство",
            "   • Регулярно обновлять информацию об устройствах",
            "",
            "2. Провести оценку уязвимостей:",
            "   • Использовать сканеры уязвимостей (Nessus, OpenVAS)",
            "   • Проверить наличие обновлений прошивок",
            "   • Оценить риски по методологии CVSS",
            "",
            "3. Разработать план замены устаревшего оборудования:",
            "   • Определить устройства, не поддерживающие современные стандарты безопасности",
            "   • Составить график замены на отечественные аналоги",
            "   • Протестировать совместимость новых устройств",
        ]
        
        for line in recommendations:
            report.append(f"  {line}")
        
        return "\n".join(report)
    
    def generate_stage2_report(self) -> str:
        """Сгенерировать отчет по этапу 2 (Шифрование)"""
        # Получаем рекомендации по шифрованию
        recommendations = self.get_encryption_recommendations()
        
        report = []
        report.append("="*80)
        report.append(f"Отчет по этапу 2: внедрение шифрования данных")
        report.append("="*80)
        
        # Основная информация
        report.append(f"\nОсновная информация")
        report.append(f"  Организация: {self.organization}")
        report.append(f"  Дата генерации: {datetime.now().strftime('%d.%m.%Y %H:%M')}")
        
        # Статистика по шифрованию
        total = len(self.devices)
        encrypted = sum(1 for d in self.devices if d.get("encryption", False))
        needs_replacement = sum(1 for d in self.devices 
                              if d.get("encryption_recommendation", {}).get("replacement_needed", False))
        
        report.append(f"\nСтатистика по шифрованию")
        report.append(f"  • Всего устройств: {total}")
        report.append(f"  • Уже используют шифрование: {encrypted} ({encrypted/total*100:.1f}%)")
        report.append(f"  • Требуют замены: {needs_replacement}")
        
        # 2.1. Криптостандарты
        report.append(f"\n" + "-"*60)
        report.append("2.1. Выбор криптостандартов (алгоритмов шифрования)")
        report.append("-"*60)
        
        crypto_recs = recommendations.get("crypto_standards", [])
        if crypto_recs:
            # Группируем по приоритету
            critical = [r for r in crypto_recs if r.get("priority") == "критический"]
            high = [r for r in crypto_recs if r.get("priority") == "высокий"]
            medium = [r for r in crypto_recs if r.get("priority") == "средний"]
            
            if critical:
                report.append(f"\n  Критический приоритет ({len(critical)} устройств):")
                for rec in critical[:3]:  # Показываем первые 3
                    report.append(f"    • {rec['device']}")
                    for action in rec.get("actions", [])[:2]:
                        report.append(f"      - {action}")
            
            if high:
                report.append(f"\n  Высокий приоритет ({len(high)} устройств):")
                for rec in high[:3]:
                    report.append(f"    • {rec['device']}")
        
        # 2.2. Защищенные каналы
        report.append(f"\n" + "-"*60)
        report.append("2.2. Настройка защищенных каналов связи")
        report.append("-"*60)
        
        channels = recommendations.get("secure_channels", [])
        if channels:
            report.append(f"\n  Обнаружено {len(channels)} групп устройств, требующих защищенных каналов:")
            for channel in channels[:3]:  # Показываем первые 3
                report.append(f"    • Группа '{channel.get('group')}': {len(channel.get('devices', []))} устройств")
                if channel.get('gateway'):
                    report.append(f"      Рекомендуемый шлюз: {channel['gateway']}")
        
        # 2.3. Управление ключами
        report.append(f"\n" + "-"*60)
        report.append("2.3. Система управления криптографическими ключами")
        report.append("-"*60)
        
        key_mgmt = recommendations.get("key_management", [])
        if key_mgmt:
            for rec in key_mgmt:
                report.append(f"\n  Устройство HSM: {rec.get('hsm_device')}")
                report.append(f"  Тип: {rec.get('type')}")
                if rec.get("recommendations"):
                    report.append("  Рекомендации:")
                    for action in rec["recommendations"][:3]:
                        report.append(f"    • {action}")
        
        # 2.4. Шифрование хранилищ
        report.append(f"\n" + "-"*60)
        report.append("2.4. Шифрование хранилищ данных")
        report.append("-"*60)
        
        storage = recommendations.get("storage_encryption", [])
        if storage:
            report.append(f"\n  Обнаружено {len(storage)} устройств с хранилищами данных:")
            for rec in storage[:3]:
                report.append(f"    • {rec.get('device')}")
                report.append(f"      Тип хранилища: {rec.get('storage_type')}")
        
        # Новое оборудование
        new_devices = recommendations.get("new_devices_to_add", [])
        if new_devices:
            report.append(f"\n" + "-"*60)
            report.append("Рекомендуемое дополнительное оборудование")
            report.append("-"*60)
            
            for device in new_devices:
                report.append(f"\n  • {device.get('type')}:")
                report.append(f"    Модель: {device.get('manufacturer')} {device.get('model')}")
                report.append(f"    Назначение: {device.get('purpose')}")
        
        # Нормативные требования
        report.append(f"\n" + "-"*60)
        report.append("Нормативные требования к шифрованию")
        report.append("-"*60)
        
        norms = [
            "• ФСТЭК Приказ №239: Требования к защите информации при передаче",
            "• ГОСТ Р 57580.1-2017: Шифрование данных в системах КИИ",
            "• Приказ ФСБ №378: Использование криптографических средств",
            "• ФЗ-152: Шифрование персональных данных",
            "• ГОСТ Р 34.10-2012: Российские алгоритмы электронной подписи",
            "• ГОСТ Р 34.11-2012: Российские хэш-функции",
            "• ГОСТ Р 34.12-2015: Блочный шифр 'Кузнечик'",
            "• ГОСТ Р 34.13-2015: Блочный шифр 'Магма'",
        ]
        
        for norm in norms:
            report.append(f"  {norm}")
        
        return "\n".join(report)
    
    def generate_stage3_report(self) -> str:
        """Сгенерировать отчет по этапу 3 (Сегментация сети)"""
        # Получаем рекомендации по сегментации
        recommendations = self.get_segmentation_recommendations()
        
        report = []
        report.append("="*80)
        report.append(f"Отчет по этапу 3: сегментация сети")
        report.append("="*80)
        
        # Основная информация
        report.append(f"\nОсновная информация")
        report.append(f"  Организация: {self.organization}")
        report.append(f"  Дата генерации: {datetime.now().strftime('%d.%m.%Y %H:%M')}")
        
        # Статистика по сегментации
        total = len(self.devices)
        physical = sum(1 for d in self.devices if d.get("physical_access", False))
        
        report.append(f"\nстатистика по сегментации")
        report.append(f"  • Всего устройств: {total}")
        report.append(f"  • Устройств с физическим доступом: {physical}")
        
        # 3.1. Устранение доверенных зон
        report.append(f"\n" + "-"*60)
        report.append("3.1. Устранение концепции «доверенных зон»")
        report.append("-"*60)
        
        trust_zones = recommendations.get("trust_zones_elimination", [])
        if trust_zones:
            # Принципы
            principles = [r for r in trust_zones if r.get("type") == "Принцип"]
            if principles:
                report.append(f"\n  Ключевые принципы zero trust:")
                for rec in principles[:4]:
                    report.append(f"    {rec.get('content')}")
            
            # Шаги реализации
            steps = [r for r in trust_zones if r.get("type") == "Шаг реализации"]
            if steps:
                report.append(f"\n  Пошаговая реализация:")
                for step in steps[:3]:
                    report.append(f"    {step.get('step')}")
                    for action in step.get("actions", [])[:2]:
                        report.append(f"      • {action}")
        
        # 3.2. Минимальные привилегии
        report.append(f"\n" + "-"*60)
        report.append("3.2. Ограничение взаимодействия по принципу минимальных привилегий")
        report.append("-"*60)
        
        privileges = recommendations.get("minimal_privileges", [])
        if privileges:
            # Показываем примеры для разных типов устройств
            device_types_shown = set()
            for rec in privileges:
                if isinstance(rec, dict) and "device" in rec:
                    device_type = rec.get("type", "")
                    if device_type not in device_types_shown:
                        device_types_shown.add(device_type)
                        report.append(f"\n  {device_type}:")
                        report.append(f"    Пример: {rec.get('device')}")
                        
                        if rec.get("required_privileges"):
                            report.append(f"    Необходимые привилегии:")
                            for priv in rec["required_privileges"][:2]:
                                report.append(f"      ✓ {priv}")
        
        # 3.3. Изолированные сегменты
        report.append(f"\n" + "-"*60)
        report.append("3.3. Реализация изолированных сегментов сети")
        report.append("-"*60)
        
        segments = recommendations.get("isolated_segments", [])
        if segments:
            # Показываем ключевые сегменты
            report.append(f"\n  Ключевые сегменты сети:")
            
            for seg in self.segmentation_planner.network_analyzer.topology.segments[:4]:
                report.append(f"\n    • {seg.name}:")
                report.append(f"      Уровень безопасности: {seg.security_level.value}")
                report.append(f"      Устройств: {len(seg.device_ids)}")
                report.append(f"      Уровень изоляции: {self.segmentation_planner._get_isolation_level(seg.security_level)}")
        
        # 3.4. Изоляция устройств с физическим доступом
        report.append(f"\n" + "-"*60)
        report.append("3.4. Логическое отделение устройств с физическим доступом")
        report.append("-"*60)
        
        physical_recs = recommendations.get("physical_access_isolation", [])
        if physical_recs:
            physical_devices = [d for d in self.devices if d.get("physical_access", False)]
            if physical_devices:
                report.append(f"\n  Устройства с физическим доступом ({len(physical_devices)} шт.):")
                for device in physical_devices[:3]:
                    risk = self.segmentation_planner._assess_location_risk(device)
                    report.append(f"    • {device.get('manufacturer')} {device.get('model')}")
                    report.append(f"      Уровень риска: {risk}")
        
        # 3.5. Сквозной контроль трафика
        report.append(f"\n" + "-"*60)
        report.append("3.5. Настройка сквозного контроля трафика")
        report.append("-"*60)
        
        traffic = recommendations.get("traffic_inspection", {})
        if traffic:
            report.append(f"\n  Рекомендуемые технологии:")
            for tech in traffic.get("recommended_technologies", [])[:2]:
                report.append(f"    • {tech.get('name')} ({tech.get('vendor')})")
                report.append(f"      Возможности: {tech.get('capabilities')}")
        
        # Нормативные требования
        report.append(f"\n" + "-"*60)
        report.append("Нормативные требования к сегментации")
        report.append("-"*60)
        
        norms = [
            "• ФСТЭК Приказ №239: Разделение сетей и контроль доступа",
            "• ГОСТ Р 57580.1-2017: Сегментация сетей КИИ",
            "• PCI DSS: Разделение сетей для платежных систем",
            "• NIST SP 800-41: Рекомендации по межсетевым экранам",
            "• ISO/IEC 27033: Безопасность сетевой инфраструктуры",
        ]
        
        for norm in norms:
            report.append(f"  {norm}")
        
        return "\n".join(report)
    
    def generate_stage4_report(self) -> str:
        """Сгенерировать отчет по этапу 4 (MFA)"""
        report = []
        report.append("="*80)
        report.append(f"Отчет по этапу 4: многофакторная аутентификация (MFA)")
        report.append("="*80)
        
        report.append(f"\nОсновная информация")
        report.append(f"  Организация: {self.organization}")
        report.append(f"  Дата генерации: {datetime.now().strftime('%d.%m.%Y %H:%M')}")
        
        report.append(f"\nАнализ текущего состояния")
        
        # Определяем устройства, требующие MFA
        mfa_devices = []
        for device in self.devices:
            if device.get("critical", False) or device.get("kii_category", 0) in [1, 2, 3]:
                mfa_devices.append(device)
        
        report.append(f"  • Устройств, требующих MFA: {len(mfa_devices)}")
        
        if mfa_devices:
            report.append(f"\n   Критические устройства, требующие MFA:")
            for device in mfa_devices[:5]:
                report.append(f"    • {device.get('manufacturer')} {device.get('model')}")
                if device.get("critical"):
                    report.append(f"      Причина: Критическое устройство")
                if device.get("kii_category", 0) > 0:
                    report.append(f"      Причина: Устройство КИИ категории {device.get('kii_category')}")
        
        report.append(f"\n" + "-"*60)
        report.append("4.1. Выбор методов аутентификации")
        report.append("-"*60)
        
        methods = [
            "• Отечественные решения:",
            "  - Яндекс.Ключ: Бесплатное решение для российских организаций",
            "  - Рутокен: Аппаратные и программные токены с поддержкой ГОСТ",
            "  - JaCarta: Универсальные средства аутентификации",
            "  - КриптоПро: Интеграция с отечественной криптографией",
            "",
            "• Зарубежные аналоги (только при отсутствии альтернатив):",
            "  - Microsoft Authenticator: Для инфраструктуры на базе Azure",
            "  - Google Authenticator: Для веб-сервисов",
            "  - Duo Security: Для сетевого оборудования",
        ]
        
        for line in methods:
            report.append(f"  {line}")
        
        report.append(f"\n" + "-"*60)
        report.append("4.2. Внедрение адаптивного доступа")
        report.append("-"*60)
        
        adaptive = [
            "• Настройка правил адаптивной аутентификации:",
            "  - Признак 1: Неизвестное устройство → Запрос второго фактора",
            "  - Признак 2: Необычное время доступа → Дополнительная проверка",
            "  - Признак 3: Подозрительная геолокация → Блокировка",
            "  - Признак 4: Частые неудачные попытки → Временная блокировка",
            "",
            "• Интеграция с siem системами:",
            "  - Splunk, ArcSight, MaxPatrol для анализа логов",
            "  - Автоматическое создание инцидентов при аномалиях",
        ]
        
        for line in adaptive:
            report.append(f"  {line}")
        
        report.append(f"\n" + "-"*60)
        report.append("4.3. Настройка политик доступа")
        report.append("-"*60)
        
        policies = [
            "• Для устройств кии (категории 1-2):",
            "  - Обязательная аппаратная MFA (Рутокен, JaCarta)",
            "  - Биометрическая аутентификация для администраторов",
            "  - Двухэтапное подтверждение критических операций",
            "",
            "• ДЛЯ КРИТИЧЕСКИХ УСТРОЙСТВ:",
            "  - MFA при каждом подключении",
            "  - Сессия не более 8 часов",
            "  - Логирование всех действий",
            "",
            "• Для обычных устройств:",
            "  - MFA при первом входе с нового устройства",
            "  - Периодическая повторная аутентификация",
        ]
        
        for line in policies:
            report.append(f"  {line}")
        
        report.append(f"\n" + "-"*60)
        report.append("НОРМАТИВНЫЕ ТРЕБОВАНИЯ К MFA")
        report.append("-"*60)
        
        norms = [
            "• ФСТЭК Приказ №239: Многофакторная аутентификация для доступа к КИИ",
            "• ГОСТ Р 57580.1-2017: Требования к аутентификации в системах КИИ",
            "• Приказ ФСТЭК №21: Защита информации в госинформационных системах",
            "• PCI DSS: MFA для удаленного доступа к платежным системам",
            "• NIST SP 800-63B: Рекомендации по аутентификации",
        ]
        
        for norm in norms:
            report.append(f"  {norm}")

        return "\n".join(report)
    
    def generate_stage5_report(self) -> str:
        """Сгенерировать отчет по этапу 5 (Мониторинг и поддержка)"""
        report = []
        report.append("="*80)
        report.append(f"Отчет по этапу 5: мониторинг и поддержка")
        report.append("="*80)
        
        report.append(f"\nОсновная информация")
        report.append(f"  Организация: {self.organization}")
        report.append(f"  Дата генерации: {datetime.now().strftime('%d.%m.%Y %H:%M')}")
        
        report.append(f"\nАнализ текущего состояния")
        
        # Определяем устройства для мониторинга
        monitor_devices = []
        for device in self.devices:
            if device.get("critical", False) or device.get("data_volume") in ["высокая", "средняя"]:
                monitor_devices.append(device)
        
        report.append(f"  • Устройств, требующих мониторинга: {len(monitor_devices)}")
        
        if monitor_devices:
            report.append(f"\n  Ключевые устройства для мониторинга:")
            for device in monitor_devices[:5]:
                report.append(f"    • {device.get('manufacturer')} {device.get('model')}")
                if device.get("critical"):
                    report.append(f"      Приоритет: высокий (критическое устройство)")
        
        report.append(f"\n" + "-"*60)
        report.append("5.1. Внедрение поведенческого анализа")
        report.append("-"*60)
        
        behavioral = [
            "• Основные метрики для анализа:",
            "  - Объем передаваемых данных (аномальные всплески)",
            "  - Время активности (несанкционированное время работы)",
            "  - Геолокация подключений (неожиданные локации)",
            "  - Частота запросов (признаки DDoS атак)",
            "",
            "• Технологии для реализации:",
            "  - Машинное обучение: Darktrace, Vectra, ExtraHop",
            "  - Статистический анализ: Splunk ML, Elastic ML",
            "  - Правила корреляции: в SIEM системах",
        ]
        
        for line in behavioral:
            report.append(f"  {line}")
        
        report.append(f"\n" + "-"*60)
        report.append("5.2. Автоматизация ответа на инциденты")
        report.append("-"*60)
        
        automation = [
            "• Сценарии автоматического реагирования:",
            "  - Обнаружение подозрительного трафика → Изоляция устройства",
            "  - Множественные неудачные попытки входа → Блокировка IP",
            "  - Попытка доступа к критическим ресурсам → Оповещение SOC",
            "  - Изменение конфигурации устройства → Откат и оповещение",
            "",
            "• Интеграция с soar платформами:",
            "  - IBM Resilient, Splunk Phantom, Microsoft Sentinel",
            "  - Автоматическое создание инцидентов",
            "  - Предопределенные playbook для реагирования",
        ]
        
        for line in automation:
            report.append(f"  {line}")
        
        report.append(f"\n" + "-"*60)
        report.append("5.3. ДИНАМИЧЕСКОЕ ИЗМЕНЕНИЕ УРОВНЯ ДОСТУПА")
        report.append("-"*60)
        
        dynamic = [
            "• ФАКТОРЫ ДЛЯ ИЗМЕНЕНИЯ УРОВНЯ ДОВЕРИЯ:",
            "  - Health Score устройства (состояние безопасности)",
            "  - Контекст доступа (время, местоположение, устройство)",
            "  - Поведенческие аномалии (отклонения от baseline)",
            "  - Угрозы в реальном времени (CTI feeds)",
            "",
            "• МЕХАНИЗМЫ РЕАЛИЗАЦИИ:",
            "  - Политики Conditional Access в Azure AD",
            "  - Cisco Identity Services Engine (ISE)",
            "  - Okta Adaptive MFA",
        ]
        
        for line in dynamic:
            report.append(f"  {line}")
        
        report.append(f"\n" + "-"*60)
        report.append("НОРМАТИВНЫЕ ТРЕБОВАНИЯ К МОНИТОРИНГУ")
        report.append("-"*60)
        
        norms = [
            "• ФСТЭК Приказ №239: Мониторинг и реагирование на инциденты",
            "• ГОСТ Р 57580.1-2017: Мониторинг систем КИИ",
            "• ISO/IEC 27035: Управление инцидентами информационной безопасности",
            "• NIST SP 800-61: Рекомендации по обработке инцидентов",
            "• PCI DSS: Непрерывный мониторинг и тестирование",
        ]
        
        for norm in norms:
            report.append(f"  {norm}")
        
        return "\n".join(report)
    
    def generate_full_report(self) -> str:
        """Сгенерировать полный отчет по всем этапам"""
        report = []

        # Титульная страница
        report.append("="*80)
        report.append("ПОЛНЫЙ ПЛАН ПО ВНЕДРЕНИЮ МОДЕЛИ ZERO TRUST")
        report.append("="*80)
        
        report.append(f"\nОсновная информация")
        report.append(f"  Организация: {self.organization}")
        report.append(f"  Дата создания инфраструктуры: {self.created_at[:10]}")
        report.append(f"  Дата генерации отчета: {datetime.now().strftime('%d.%m.%Y %H:%M')}")
        report.append(f"  Всего устройств в инфраструктуре: {len(self.devices)}")
        
        report.append(f"\nКлючевая статистика")
        
        critical = sum(1 for d in self.devices if d.get("critical", False))
        kii = sum(1 for d in self.devices if d.get("kii_category", 0) in [1, 2])
        encrypted = sum(1 for d in self.devices if d.get("encryption", False))
        physical = sum(1 for d in self.devices if d.get("physical_access", False))
        needs_replacement = sum(1 for d in self.devices 
                              if d.get("encryption_recommendation", {}).get("replacement_needed", False))
        
        report.append(f"  • Критических устройств: {critical}")
        report.append(f"  • Устройств КИИ 1-2 категории: {kii}")
        report.append(f"  • Устройств с шифрованием: {encrypted} ({encrypted/len(self.devices)*100:.1f}%)")
        report.append(f"  • Устройств с физическим доступом: {physical}")
        report.append(f"  • Устройств, требующих замены: {needs_replacement}")
        
        report.append(f"\nПриоритеты внедрения")
        priorities = [
            "1. Устройства КИИ 1-2 категории без шифрования",
            "2. Критические устройства с физическим доступом",
            "3. Импортное оборудование с известными уязвимостями",
            "4. Устройства без шифрования в корпоративной сети",
            "5. Оборудование с паролями по умолчанию",
        ]
        
        for priority in priorities:
            report.append(f"  {priority}")
        
        report.append(f"\nРекомендуемый график внедрения")
        schedule = [
            "Месяц 1-2: Инвентаризация и оценка рисков (Этап 1)",
            "Месяц 3-4: Внедрение шифрования (Этап 2)",
            "Месяц 5-6: Сегментация сети (Этап 3)",
            "Месяц 7-8: Настройка MFA (Этап 4)",
            "Месяц 9-12: Внедрение мониторинга (Этап 5)",
        ]
        
        for item in schedule:
            report.append(f"  {item}")
        
        # Добавляем все этапы
        report.append(f"\n" + "="*80)
        report.append(f"ЭТАП 1: ИНВЕНТАРИЗАЦИЯ УСТРОЙСТВ")
        report.append("="*80)
        report.append(self.generate_stage1_report().split("="*80)[-1])
        
        report.append(f"\n" + "="*80)
        report.append(f"ЭТАП 2: ВНЕДРЕНИЕ ШИФРОВАНИЯ ДАННЫХ")
        report.append("="*80)
        report.append(self.generate_stage2_report().split("="*80)[-1])
        
        report.append(f"\n" + "="*80)
        report.append(f"ЭТАП 3: СЕГМЕНТАЦИЯ СЕТИ")
        report.append("="*80)
        report.append(self.generate_stage3_report().split("="*80)[-1])
        
        report.append(f"\n" + "="*80)
        report.append(f"ЭТАП 4: МНОГОФАКТОРНАЯ АУТЕНТИФИКАЦИЯ (MFA)")
        report.append("="*80)
        report.append(self.generate_stage4_report().split("="*80)[-1])
        
        report.append(f"\n" + "="*80)
        report.append(f"ЭТАП 5: МОНИТОРИНГ И ПОДДЕРЖКА")
        report.append("="*80)
        report.append(self.generate_stage5_report().split("="*80)[-1])
        
        # Заключение
        report.append(f"\n" + "="*80)
        report.append(f"ЗАКЛЮЧЕНИЕ И РЕКОМЕНДАЦИИ")
        report.append("="*80)
        
        conclusion = [
            "Основные риски:",
            "  • Наличие устройств без шифрования",
            "  • Устройства с физическим доступом",
            "  • Импортное оборудование с потенциальными backdoor",
            "",
            "Ключевые рекомендации:",
            "  1. Начать с замены критических устройств без шифрования",
            "  2. Внедрить сегментацию для изоляции рисков",
            "  3. Обязательно использовать отечественные решения шифрования",
            "  4. Реализовать MFA для всех административных доступов",
            "  5. Настроить централизованный мониторинг",
            "",
            "Ориентировочная стоимость внедрения:",
            "  • Оборудование и ПО: от 3,000,000 руб.",
            "  • Услуги внедрения: от 2,000,000 руб.",
            "  • Обучение персонала: от 500,000 руб.",
            "  • ИТОГО: от 5,500,000 руб.",
            "",
            "Ориентировочные сроки:",
            "  • Полное внедрение: 6-12 месяцев",
            "  • Первые результаты: через 2-3 месяца",
            "  • Полное соответствие требованиям: 12-18 месяцев",
        ]
        
        for line in conclusion:
            report.append(f"  {line}")
        
                # Рассчитываем RZT
        zti_analysis = self.calculate_zti_analysis()
        
        # Добавляем RZT отчет в начало
        report.append(ZTICalculator.generate_zti_report(
            zti_analysis["initial"],
            zti_analysis["stages"],
            zti_analysis["final"]
        ))
        

        report.append(f"\n" + "="*80)
        report.append(f"Отчет сгенерирован автоматически системой ZeroTrustModeller")
        report.append(f"Дата: {datetime.now().strftime('%d.%m.%Y %H:%M')}")
        report.append("="*80)
        
        return "\n".join(report)
    
    def save_report(self, report_text: str, filename: str) -> str:
        """Сохранить отчет в файл"""
        # Создаем директорию reports если её нет
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        filepath = reports_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report_text)
        
        return str(filepath)