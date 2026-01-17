"""
Генератор полных отчетов ZeroTrustModeller
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, List
from modules.encryption_planner import EncryptionPlanner
from modules.zti_calculator import ZTICalculator

class ReportGenerator:
    """Генератор полных отчетов по всем этапам Zero Trust"""
    
    def __init__(self, infrastructure: Dict):
        self.infrastructure = infrastructure
        self.devices = infrastructure.get("devices", [])
        self.organization = infrastructure.get("organization", "Неизвестная организация")
        self.created_at = infrastructure.get("created_at", datetime.now().isoformat())
        self.updated_at = infrastructure.get("updated_at", datetime.now().isoformat())
    
    def generate_stage1_report(self) -> str:
        """Сгенерировать отчет по этапу 1 (Инвентаризация)"""
        report = []
        report.append("\n" + "="*80)
        report.append("ЭТАП 1: ИНВЕНТАРИЗАЦИЯ И АНАЛИЗ УСТРОЙСТВ")
        report.append("="*80)
        
        if not self.devices:
            report.append("\nНет данных об устройствах.")
            return "\n".join(report)
        
        # Статистика
        total = len(self.devices)
        critical = sum(1 for d in self.devices if d.get("critical", False))
        kii_1_2 = sum(1 for d in self.devices if d.get("kii_category", 0) in [1, 2])
        physical_access = sum(1 for d in self.devices if d.get("physical_access", False))
        has_encryption = sum(1 for d in self.devices if d.get("encryption", False))
        
        report.append(f"\nСТАТИСТИКА ИНФРАСТРУКТУРЫ:")
        report.append(f"  Всего устройств: {total}")
        report.append(f"  Критических устройств: {critical}")
        report.append(f"  Устройств КИИ 1-2 категории: {kii_1_2}")
        report.append(f"  С физическим доступом: {physical_access}")
        report.append(f"  С шифрованием: {has_encryption} ({has_encryption/total*100:.1f}%)")
        
        # Анализ по категориям
        report.append("\nАНАЛИЗ ПО КАТЕГОРИЯМ:")
        categories = {}
        for device in self.devices:
            cat = device.get("category", "Без категории")
            if cat not in categories:
                categories[cat] = {"count": 0, "encrypted": 0, "critical": 0}
            categories[cat]["count"] += 1
            if device.get("encryption"):
                categories[cat]["encrypted"] += 1
            if device.get("critical"):
                categories[cat]["critical"] += 1
        
        for cat, data in categories.items():
            perc = data["encrypted"]/data["count"]*100 if data["count"] > 0 else 0
            report.append(f"  • {cat}: {data['count']} устройств, {data['encrypted']} с шифрованием ({perc:.1f}%), "
                         f"критических: {data['critical']}")
        
        # Группы взаимодействия
        report.append("\nГРУППЫ ВЗАИМОДЕЙСТВИЯ:")
        groups = {}
        for device in self.devices:
            group = device.get("interaction_group", "без группы")
            if group not in groups:
                groups[group] = []
            groups[group].append(device)
        
        for group, devices in groups.items():
            report.append(f"  • {group}: {len(devices)} устройств")
            if len(devices) > 1:
                protocols = set()
                for d in devices:
                    protocols.update(d.get("protocols", []))
                report.append(f"    Общие протоколы: {', '.join(protocols)[:100]}...")
        
        # Обнаруженные уязвимости и риски
        report.append("\nВЫЯВЛЕННЫЕ РИСКИ:")
        
        # 1. Устройства без шифрования
        no_encryption = [d for d in self.devices if not d.get("encryption", False)]
        if no_encryption:
            report.append("\n  1. УСТРОЙСТВА БЕЗ ШИФРОВАНИЯ:")
            for device in no_encryption[:10]:  # Ограничим вывод
                report.append(f"     • {device.get('manufacturer')} {device.get('model')} (ID: {device.get('id')})")
            if len(no_encryption) > 10:
                report.append(f"     ... и еще {len(no_encryption)-10} устройств")
        
        # 2. Импортное оборудование с высоким риском
        import_high_risk = [d for d in self.devices 
                           if d.get("manufacturer", "") not in ["Овен", "Элвис-Нео", "Ростелеком", "Болид", "Киберлок"]
                           and d.get("risk_level") in ["high", "critical"]]
        if import_high_risk:
            report.append("\n  2. ИМПОРТНОЕ ОБОРУДОВАНИЕ С ВЫСОКИМ РИСКОМ:")
            for device in import_high_risk[:5]:
                report.append(f"     • {device.get('manufacturer')} {device.get('model')} - риск: {device.get('risk_level')}")
                if device.get("default_credentials"):
                    report.append(f"       Слабые учетные данные по умолчанию!")
        
        # 3. Устройства с физическим доступом
        physical_devices = [d for d in self.devices if d.get("physical_access", False)]
        if physical_devices:
            report.append("\n  3. УСТРОЙСТВА С ФИЗИЧЕСКИМ ДОСТУПОМ:")
            for device in physical_devices[:5]:
                report.append(f"     • {device.get('manufacturer')} {device.get('model')} - {device.get('type')}")
        
        # 4. Критические устройства без шифрования
        critical_no_enc = [d for d in self.devices 
                          if d.get("critical", False) and not d.get("encryption", False)]
        if critical_no_enc:
            report.append("\n  4. КРИТИЧЕСКИЕ УСТРОЙСТВА БЕЗ ШИФРОВАНИЯ (ВЫСОКИЙ ПРИОРИТЕТ):")
            for device in critical_no_enc:
                report.append(f"     {device.get('manufacturer')} {device.get('model')} - требует немедленного внимания!")
        
        # Рекомендации по этапу 1
        report.append("\n" + "-"*80)
        report.append("РЕКОМЕНДАЦИИ ПО ЭТАПУ 1:")
        report.append("-"*80)
        
        # 1. Создать полный реестр
        report.append("\n  1. СОЗДАТЬ ЦЕНТРАЛИЗОВАННЫЙ РЕЕСТР УСТРОЙСТВ:")
        report.append("     • Завести базу данных всех IoT-устройств с полями: ID, тип, IP, владелец, ответственность")
        report.append("     • Реализовать систему автоматического обнаружения новых устройств")
        report.append("     • Назначить ответственных за каждое устройство")
        
        # 2. Оценить уязвимости
        report.append("\n  2. ОЦЕНИТЬ УЯЗВИМОСТИ И РИСКИ:")
        report.append("     • Провести сканирование уязвимостей (OpenVAS, Nessus)")
        report.append("     • Проверить наличие CVE для каждого устройства")
        report.append("     • Оценить критичность по методике CVSS")
        
        # 3. План замены
        report.append("\n  3. РАЗРАБОТАТЬ ПЛАН ЗАМЕНЫ:")
        
        # Устройства, требующие замены
        needs_replacement = []
        for device in self.devices:
            rec = device.get("encryption_replacement", {})
            if rec.get("replacement_needed", False):
                needs_replacement.append(device)
        
        if needs_replacement:
            report.append("     • Устройства, требующие замены:")
            for device in needs_replacement:
                report.append(f"       - {device.get('manufacturer')} {device.get('model')}")
                suggestion = device.get("replacement_suggestion")
                if suggestion:
                    report.append(f"         Замена на: {suggestion}")
        else:
            report.append("     • Серьезных проблем с совместимостью не обнаружено")
        
        # 4. Тестирование совместимости
        report.append("\n  4. ПРОТЕСТИРОВАТЬ СОВМЕСТИМОСТЬ:")
        report.append("     • Создать тестовый стенд с типовыми сценариями работы")
        report.append("     • Проверить работу отечественных алгоритмов шифрования")
        report.append("     • Протестировать интеграцию новых устройств в существующую инфраструктуру")
        
        # 5. Документация
        report.append("\n  5. ОБНОВИТЬ ДОКУМЕНТАЦИЮ:")
        report.append("     • Создать схемы сети с устройствами IoT")
        report.append("     • Задокументировать все точки подключения и интерфейсы")
        report.append("     • Создать регламенты обслуживания для каждого типа устройств")
        
        return "\n".join(report)
    
    def generate_stage2_report(self) -> str:
        """Сгенерировать отчет по этапу 2 (Шифрование)"""
        # Используем существующий EncryptionPlanner
        planner = EncryptionPlanner(self.infrastructure)
        recommendations = planner.analyze_infrastructure()
        
        report = []
        report.append("\n" + "="*80)
        report.append("ЭТАП 2: ВНЕДРЕНИЕ ШИФРОВАНИЯ ДАННЫХ")
        report.append("="*80)
        
        # Статистика по этапу 2
        total = len(self.devices)
        no_encryption = sum(1 for d in self.devices if not d.get("encryption", False))
        needs_replacement = sum(1 for d in self.devices 
                              if d.get("encryption_recommendation", {}).get("replacement_needed", False))
        
        report.append(f"\n АНАЛИЗ ШИФРОВАНИЯ:")
        report.append(f"  Всего устройств: {total}")
        report.append(f"  Без шифрования: {no_encryption} ({no_encryption/total*100:.1f}%)")
        report.append(f"  Требуют замены: {needs_replacement}")
        
        # Критические проблемы
        critical_issues = []
        for device in self.devices:
            if device.get("kii_category", 0) in [1, 2] and not device.get("encryption", False):
                critical_issues.append(device)
        
        if critical_issues:
            report.append("\nКРИТИЧЕСКИЕ ПРОБЛЕМЫ:")
            for device in critical_issues:
                report.append(f"  • {device.get('manufacturer')} {device.get('model')} - КИИ без шифрования!")
        
        # Основные рекомендации (кратко, подробности в отдельных отчетах EncryptionPlanner)
        report.append("\n" + "-"*80)
        report.append("КРАТКИЕ РЕКОМЕНДАЦИИ ПО ЭТАПУ 2:")
        report.append("(подробные инструкции в отдельных отчетах по каждому подэтапу)")
        report.append("-"*80)
        
        # 2.1. Криптостандарты
        report.append("\n  2.1. ВЫБОР КРИПТОСТАНДАРТОВ:")
        
        # Группируем рекомендации по приоритету
        high_priority = []
        medium_priority = []
        
        for rec in recommendations.get("crypto_standards", []):
            if rec.get("priority") == "критический":
                high_priority.append(rec)
            else:
                medium_priority.append(rec)
        
        if high_priority:
            report.append("     КРИТИЧЕСКИЙ ПРИОРИТЕТ:")
            for rec in high_priority[:3]:  # Ограничим вывод
                report.append(f"     • {rec['device']}: {rec['actions'][0][:100]}...")
        
        if medium_priority:
            report.append("\n     СРЕДНИЙ ПРИОРИТЕТ:")
            for rec in medium_priority[:3]:
                report.append(f"     • {rec['device']}: требует настройки шифрования")
        
        # 2.2. Защищенные каналы
        report.append("\n  2.2. ЗАЩИЩЕННЫЕ КАНАЛЫ:")
        secure_channels = recommendations.get("secure_channels", [])
        if secure_channels:
            for rec in secure_channels[:2]:  # Покажем 2 группы
                report.append(f"     • Группа '{rec['group']}': {len(rec['devices'])} устройств")
                if rec.get('gateway'):
                    report.append(f"       Шлюз: {rec['gateway']}")
        
        # 2.3. Управление ключами
        report.append("\n  2.3. УПРАВЛЕНИЕ КЛЮЧАМИ:")
        key_mgmt = recommendations.get("key_management", [])
        if key_mgmt:
            for rec in key_mgmt:
                report.append(f"     • HSM: {rec['hsm_device']}")
                report.append(f"       Тип: {rec['type']}")
                break  # Только первый
        
        # 2.4. Шифрование хранилищ
        report.append("\n  2.4. ШИФРОВАНИЕ ХРАНИЛИЩ:")
        storage = recommendations.get("storage_encryption", [])
        if storage:
            report.append(f"     • Устройств с хранилищами: {len(storage)}")
            for rec in storage[:2]:
                report.append(f"       - {rec['device']}: {rec['storage_type']}")
        
        # Новые устройства для покупки
        new_devices = recommendations.get("new_devices_to_add", [])
        if new_devices:
            report.append("\n  2.5. РЕКОМЕНДУЕМЫЕ ПОКУПКИ:")
            for device in new_devices:
                report.append(f"     • {device['type']}: {device['manufacturer']} {device['model']}")
                report.append(f"       Назначение: {device['purpose']}")
        
        return "\n".join(report)
    
    def generate_full_report(self) -> str:
        """Сгенерировать полный отчет по всем этапам"""
        report = []

        # Рассчитываем ZTI
        zti_analysis = self.calculate_zti_analysis()
        
        # Добавляем ZTI отчет в начало
        report.append(ZTICalculator.generate_zti_report(
            zti_analysis["initial"],
            zti_analysis["stages"],
            zti_analysis["final"]
        ))

        
        # Заголовок
        report.append("="*80)
        report.append("ПОЛНЫЙ ОТЧЕТ ПО ВНЕДРЕНИЮ МОДЕЛИ ZERO TRUST")
        report.append("="*80)
        report.append(f"Организация: {self.organization}")
        report.append(f"Дата создания инфраструктуры: {self.created_at[:10]}")
        report.append(f"Последнее обновление: {self.updated_at[:10]}")
        report.append(f"Всего устройств в инфраструктуре: {len(self.devices)}")
        report.append(f"Дата генерации отчета: {datetime.now().strftime('%d.%m.%Y %H:%M')}")
        report.append("="*80)
        
        # Введение
        report.append("\nВВЕДЕНИЕ")
        report.append("-"*40)
        report.append("Данный отчет содержит анализ текущего состояния IoT-инфраструктуры")
        report.append("и пошаговый план внедрения модели Zero Trust в соответствии с")
        report.append("требованиями российских стандартов безопасности (ФСТЭК, ГОСТ).")
        report.append("\nЭтапы внедрения:")
        report.append("1. Инвентаризация устройств и анализ рисков")
        report.append("2. Внедрение шифрования данных")
        report.append("3. Сегментация сети")
        report.append("4. Многофакторная аутентификация")
        report.append("5. Мониторинг и поддержка")
        
        # Этап 1
        report.append(self.generate_stage1_report())
        
        # Этап 2
        report.append(self.generate_stage2_report())
        
        # Этапы 3-5 (заглушки)
        report.append(self._generate_stage_stub(3, "СЕГМЕНТАЦИЯ СЕТИ"))
        report.append(self._generate_stage_stub(4, "МНОГОФАКТОРНАЯ АУТЕНТИФИКАЦИЯ"))
        report.append(self._generate_stage_stub(5, "МОНИТОРИНГ И ПОДДЕРЖКА"))
        
        # Заключение
        report.append("\n" + "="*80)
        report.append("ЗАКЛЮЧЕНИЕ И ДАЛЬНЕЙШИЕ ШАГИ")
        report.append("="*80)
        
        # Итоговая статистика
        total = len(self.devices)
        no_enc = sum(1 for d in self.devices if not d.get("encryption", False))
        crit = sum(1 for d in self.devices if d.get("critical", False))
        needs_rep = sum(1 for d in self.devices 
                       if d.get("encryption_recommendation", {}).get("replacement_needed", False))
        
        report.append(f"\nИТОГОВАЯ СТАТИСТИКА:")
        report.append(f"  • Всего проанализировано устройств: {total}")
        report.append(f"  • Устройств без шифрования: {no_enc}")
        report.append(f"  • Критических устройств: {crit}")
        report.append(f"  • Устройств, требующих замены: {needs_rep}")
        
        # Приоритеты внедрения
        report.append("\nПРИОРИТЕТЫ ВНЕДРЕНИЯ:")
        report.append("  1. Устройства КИИ без шифрования")
        report.append("  2. Критические устройства без шифрования")
        report.append("  3. Устройства с физическим доступом")
        report.append("  4. Импортное оборудование с уязвимостями")
        report.append("  5. Остальные устройства")
        
        # Рекомендуемый график
        report.append("\nРЕКОМЕНДУЕМЫЙ ГРАФИК ВНЕДРЕНИЯ:")
        report.append("  Неделя 1-2: Анализ и планирование")
        report.append("  Неделя 3-4: Закупка недостающего оборудования")
        report.append("  Неделя 5-8: Внедрение шифрования (Этап 2)")
        report.append("  Неделя 9-12: Сегментация сети (Этап 3)")
        report.append("  Неделя 13-16: Настройка MFA (Этап 4)")
        report.append("  Неделя 17-20: Внедрение мониторинга (Этап 5)")
        
        # Нормативные требования
        report.append("\nНОРМАТИВНЫЕ ТРЕБОВАНИЯ:")
        report.append("  • ФСТЭК Приказ №239: Требования к защите информации")
        report.append("  • ГОСТ Р 57580.1-2017: Безопасность КИИ")
        report.append("  • ФЗ-152: О персональных данных")
        report.append("  • ФЗ-187: О безопасности КИИ")
        report.append("  • Приказ ФСБ №378: Об использовании криптосредств")
        
        # Контакты для связи
        report.append("\nКОНТАКТЫ:")
        report.append("  • Ответственный за безопасность: [Указать ФИО]")
        report.append("  • Технический специалист: [Указать ФИО]")
        report.append("  • Контактный телефон: [Указать]")
        report.append("  • Email: [Указать]")
        
        report.append("\n" + "="*80)
        report.append("Отчет сгенерирован автоматически системой ZeroTrustModeller")
        report.append("="*80)
        
        return "\n".join(report)
    
    def _generate_stage_stub(self, stage_num: int, stage_name: str) -> str:
        report = []
        report.append("\n" + "="*80)
        report.append(f"ЭТАП {stage_num}: {stage_name}")
        report.append("="*80)
        
        if stage_num == 3:
            report.append("Содержание этапа 3:")
            report.append("• Устранение концепции 'доверенных зон'")
            report.append("• Ограничение взаимодействия по принципу минимальных привилегий")
            report.append("• Создание изолированных сегментов сети")
            report.append("• Настройка сквозного контроля трафика")
            
        elif stage_num == 4:
            report.append("Содержание этапа 4:")
            report.append("• Выбор методов аутентификации")
            report.append("• Внедрение адаптивного доступа")
            report.append("• Настройка политик MFA")
            report.append("• Защита административных интерфейсов")
            
        elif stage_num == 5:
            report.append("Содержание этапа 5:")
            report.append("• Внедрение поведенческого анализа")
            report.append("• Автоматизация ответа на инциденты")
            report.append("• Динамическое изменение уровня доступа")
            report.append("• Верификация встроенного ПО")
        
        report.append("\nДля получения подробных рекомендаций по этому этапу")
        report.append("обратитесь к разработчикам системы или дождитесь обновления.")
        
        return "\n".join(report)
    
    def save_report(self, filename: str = None) -> str:
        """Сохранить отчет в файл"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"zero_trust_report_{timestamp}.txt"
        
        report_text = self.generate_full_report()
        
        # Создаем директорию reports если её нет
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        filepath = reports_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report_text)
        
        return str(filepath)
    
    def print_summary(self):
        """Вывести краткое содержание отчета"""
        report_text = self.generate_full_report()
        
        # Находим основные разделы
        lines = report_text.split('\n')
        
        print("\n" + "="*80)
        print("КРАТКОЕ СОДЕРЖАНИЕ ОТЧЕТА")
        print("="*80)
        
        # Показываем только ключевые моменты
        sections_to_show = [
            "СТАТИСТИКА ИНФРАСТРУКТУРЫ:",
            "ВЫЯВЛЕННЫЕ РИСКИ:",
            "АНАЛИЗ ШИФРОВАНИЯ:",
            "КРИТИЧЕСКИЕ ПРОБЛЕМЫ:",
            "ИТОГОВАЯ СТАТИСТИКА:",
            "ПРИОРИТЕТЫ ВНЕДРЕНИЯ:"
        ]
        
        for i, line in enumerate(lines):
            for section in sections_to_show:
                if section in line:
                    print(line)
                    # Печатаем следующие 2-3 строки
                    for j in range(1, 4):
                        if i + j < len(lines) and lines[i + j].strip():
                            print(lines[i + j])
                    print()
                    break
        
        print("="*80)
        print("Полный отчет доступен в файле (более 1000 строк)")

    def calculate_zti_analysis(self) -> Dict:
        """Рассчитать анализ ZTI для всех этапов"""
        # Исходный ZTI
        initial_zti = ZTICalculator.calculate_initial_zti(self.devices)
        
        # ZTI по этапам
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
        
        # Итоговый ZTI
        final_zti = ZTICalculator.calculate_final_zti(self.devices)
        
        return {
            "initial": initial_zti,
            "stages": stage_zti_list,
            "final": final_zti
        }