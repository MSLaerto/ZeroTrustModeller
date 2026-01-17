#!/usr/bin/env python3
"""
ZeroTrustModeller - Программа для моделирования внедрения Zero Trust в IoT
"""

import os
import sys
from datetime import datetime

from modules.inventory import InventoryManager
from modules.encryption_planner import EncryptionPlanner
from modules.segmentation_planner import SegmentationPlanner
from modules.report_system import ReportSystem
from modules.zti_calculator import ZTICalculator
from modules.monitoring_planner import MonitoringPlanner

def show_banner():
    """Показать заголовок программы"""
    print("=" * 60)
    print("ZeroTrustModeller - Моделирование Zero Trust для IoT")
    print("Адаптировано под требования ФСТЭК и российские стандарты")
    print("=" * 60)


def show_zti_analysis():
    """Показать анализ индекса Zero Trust"""
    print("\n" + "="*80)
    print("АНАЛИЗ ИНДЕКСА ВНЕДРЕНИЯ ZERO TRUST (ZTI)")
    print("="*80)
    
    # Загружаем инфраструктуру
    inventory_manager = InventoryManager()
    
    if not inventory_manager.infrastructure["devices"]:
        print("\n❌ Ошибка: Нет устройств для анализа!")
        print("Сначала добавьте устройства через Этап 1 (Инвентаризация)")
        return

    
    devices = inventory_manager.infrastructure["devices"]
    initial_zti = ZTICalculator.calculate_initial_zti(devices)
    final_zti = ZTICalculator.calculate_final_zti(devices)
    
    print(f"\n📊 ИСХОДНЫЙ ZTI:")
    print(f"  Индекс: {initial_zti['zti_percentage']:.1f}% ({initial_zti['zti_score']:.3f})")
    
    print(f"\n📈 ПРОГНОЗИРУЕМЫЙ ZTI ПОСЛЕ ВНЕДРЕНИЯ:")
    print(f"  Индекс: {final_zti['zti_percentage']:.1f}% ({final_zti['zti_score']:.3f})")
    print(f"  Оценка: {final_zti['assessment']}")
    
    print(f"\n📋 КОМПОНЕНТЫ ZTI:")
    print(f"  • Шифрование (E): {initial_zti['components']['encryption']:.1f}% → {final_zti['components']['encryption']:.1f}%")
    print(f"  • Импортные устройства (IM): {initial_zti['components']['import_devices']:.1f}% → {final_zti['components']['import_devices']:.1f}%")
    print(f"  • Сегментация (SE): {initial_zti['components']['segmentation']:.1f}% → {final_zti['components']['segmentation']:.1f}%")
    print(f"  • MFA: {initial_zti['components']['mfa']:.1f}% → {final_zti['components']['mfa']:.1f}%")
    
    print(f"\n💡 ОСНОВНЫЕ МЕРЫ ДЛЯ ПОВЫШЕНИЯ ZTI:")
    for rec in final_zti.get('recommendations', []):
        print(f"  • {rec}")
    
    print(f"\n" + "="*80)

def main_menu():
    """Главное меню программы"""
    while True:
        print("\nГЛАВНОЕ МЕНЮ")
        print("1. Инвентаризация устройств (Этап 1)")
        print("2. Анализ шифрования (Этап 2)")
        print("3. Планирование сегментации (Этап 3)")
        print("4. Анализ и планирование MFA (Этап 4)")
        print("5. Анализ и планирование мониторинга (Этап 5)")
        print("-" * 40)
        print("6. Анализ индекса Zero Trust (RZT)")
        print("7. Сформировать отчет по этапу 1 (Инвентаризация)")
        print("8. Сформировать отчет по этапу 2 (Шифрование)")
        print("9. Сформировать отчет по этапу 3 (Сегментация сети)")
        print("10. Сформировать отчет по этапу 4 (MFA)")
        print("11. Сформировать отчет по этапу 5 (Мониторинг)")
        print("12. Сформировать полный отчет (все этапы + RZT)")
        print("0. Выход")
        
        choice = input("\nВыберите действие: ").strip()
        
        if choice == "0":
            if input("Вы уверены, что хотите выйти? (да/нет): ").lower() == "да":
                print("Программа завершена. До свидания!")
                sys.exit(0)
        elif choice == "1":
            inventory_manager = InventoryManager()
            inventory_manager.run()
        elif choice == "2":
            execute_encryption_analysis()
        elif choice == "3":
            execute_segmentation_analysis()
        elif choice == "4":
            execute_mfa_analysis()
        elif choice == "5":
            execute_monitoring_analysis()
        elif choice == "6":
            show_zti_analysis()
        elif choice in ["7", "8", "9", "10", "11"]:
            generate_report(choice)
        elif choice == "12":
            generate_report(choice)
        else:
            print("Функционал в разработке...")

def execute_encryption_analysis():
    """Выполнить анализ шифрования (Этап 2)"""
    print("\n" + "="*60)
    print("ЗАПУСК ЭТАПА 2: АНАЛИЗ ШИФРОВАНИЯ")
    print("="*60)
    
    # Загружаем текущую инфраструктуру
    inventory_manager = InventoryManager()
    
    if not inventory_manager.infrastructure["devices"]:
        print("\nОшибка: Нет устройств для анализа!")
        print("Сначала добавьте устройства через Этап 1 (Инвентаризация)")
        return
    
    print(f"\nЗагружено устройств: {len(inventory_manager.infrastructure['devices'])}")
    
    # Создаем планировщик шифрования
    planner = EncryptionPlanner(inventory_manager.infrastructure)
    
    # Анализируем инфраструктуру
    recommendations = planner.analyze_infrastructure()
    
    # Показываем краткое содержание
    planner.print_summary()
    
    print("\n" + "="*60)
    print("АНАЛИЗ ЗАВЕРШЕН!")
    print("Для получения детального отчета выберите пункт 7 в главном меню")
    print("="*60)

def execute_segmentation_analysis():
    """Выполнить анализ сегментации (Этап 3)"""
    print("\n" + "="*80)
    print("ЗАПУСК ЭТАПА 3: АНАЛИЗ И ПЛАНИРОВАНИЕ СЕГМЕНТАЦИИ СЕТИ")
    print("="*80)
    
    # Загружаем текущую инфраструктуру
    inventory_manager = InventoryManager()
    
    if not inventory_manager.infrastructure["devices"]:
        print("\nОшибка: Нет устройств для анализа!")
        print("Сначала добавьте устройства через Этап 1 (Инвентаризация)")
        return
    
    print(f"\nЗагружено устройств: {len(inventory_manager.infrastructure['devices'])}")
    
    # Создаем планировщик сегментации
    planner = SegmentationPlanner(inventory_manager.infrastructure)
    
    # Анализируем инфраструктуру
    recommendations = planner.analyze_infrastructure()
    
    # Показываем краткое содержание
    planner.print_summary()
    
    print("\n" + "="*80)
    print("АНАЛИЗ ЗАВЕРШЕН!")
    print("Для получения детального отчета выберите пункт 8 в главном меню")
    print("="*80)

def execute_mfa_analysis():
    """Выполнить анализ MFA (Этап 4)"""
    print("\n" + "="*80)
    print("ЗАПУСК ЭТАПА 4: АНАЛИЗ И ПЛАНИРОВАНИЕ MFA")
    print("="*80)
    
    # Загружаем текущую инфраструктуру
    inventory_manager = InventoryManager()
    
    if not inventory_manager.infrastructure["devices"]:
        print("\nОшибка: Нет устройств для анализа!")
        print("Сначала добавьте устройства через Этап 1 (Инвентаризация)")
        return
    
    print(f"\nЗагружено устройств: {len(inventory_manager.infrastructure['devices'])}")
    
    # Создаем планировщик MFA
    from modules.mfa_planner import MFAPlanner  # Импортируем здесь, чтобы избежать циклических импортов
    planner = MFAPlanner(inventory_manager.infrastructure)
    
    # Анализируем инфраструктуру
    recommendations = planner.analyze_infrastructure()
    
    # Показываем краткое содержание
    planner.print_summary()
    
    print("\n" + "="*80)
    print("АНАЛИЗ ЗАВЕРШЕН!")
    print("Для получения детального отчета выберите пункт 9 в главном меню")
    print("="*80)


def generate_report(report_type: str):
    """Сгенерировать отчет выбранного типа"""
    
    # Загружаем текущую инфраструктуру
    inventory_manager = InventoryManager()
    
    if not inventory_manager.infrastructure["devices"]:
        print("\nОшибка: Нет устройств для анализа!")
        print("Сначала добавьте устройства через Этап 1 (Инвентаризация)")
        return
    
    print(f"\nЗагружено устройств: {len(inventory_manager.infrastructure['devices'])}")
    
    # Создаем систему отчетов
    report_system = ReportSystem(inventory_manager.infrastructure)
    
    # Определяем тип отчета
    report_types = {
        "7": ("Этап 1: Инвентаризация", report_system.generate_stage1_report, "stage1_report"),
        "8": ("Этап 2: Шифрование", report_system.generate_stage2_report, "stage2_report"),
        "9": ("Этап 3: Сегментация", report_system.generate_stage3_report, "stage3_report"),
        "10": ("Этап 4: MFA", report_system.generate_stage4_report, "stage4_report"),
        "11": ("Этап 5: Мониторинг", report_system.generate_stage5_report, "stage5_report"),
        "12": ("Полный отчет (все этапы + RZT)", report_system.generate_full_report, "full_report")
    }
    
    if report_type not in report_types:
        print("Неизвестный тип отчета")
        return
    
    title, generator_func, base_name = report_types[report_type]
    
    print(f"\n" + "="*60)
    print(f"ФОРМИРОВАНИЕ ОТЧЕТА: {title}")
    print("="*60)
    
    # Генерируем отчет
    print(f"\nГенерация отчета...")
    report_text = generator_func()
    
    # Сохраняем отчет
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{base_name}_{timestamp}.txt"
    
    filepath = report_system.save_report(report_text, filename)
    
    print(f"\nОтчет успешно сформирован!")
    print(f"Файл: {filepath}")
    print(f"Размер: {len(report_text)} символов")
    
    # Показываем статистику отчета
    lines = report_text.count('\n') + 1
    pages = lines // 50 + 1
    
    print(f"Страниц: ~{pages} (при 50 строк на страницу)")
    
    # Предлагаем показать отчет
    print(f"\n" + "-"*60)
    show_options = input("Показать отчет? (1 - начало, 2 - конец, 3 - пропустить): ").strip()
    
    if show_options == "1":
        print("\n" + "="*80)
        print("НАЧАЛО ОТЧЕТА (первые 1000 символов):")
        print("="*80)
        print(report_text[:1000])
        print("\n... (полный отчет в файле)")
        
    elif show_options == "2":
        print("\n" + "="*80)
        print("КОНЕЦ ОТЧЕТА (последние 1000 символов):")
        print("="*80)
        print(report_text[-1000:])
        print("\n... (полный отчет в файле)")
    
    print(f"\n" + "="*60)
    print("ОТЧЕТ ГОТОВ!")
    print("="*60)

def execute_monitoring_analysis():
    """Выполнить анализ системы мониторинга (Этап 5)"""
    print("\n" + "="*80)
    print("ЗАПУСК ЭТАПА 5: АНАЛИЗ И ПЛНИРОВАНИЕ СИСТЕМЫ МОНИТОРИНГА И ПОДДЕРЖКИ")
    print("="*80)
    
    # Загружаем текущую инфраструктуру
    inventory_manager = InventoryManager()
    
    if not inventory_manager.infrastructure["devices"]:
        print("\nОшибка: Нет устройств для анализа!")
        print("Сначала добавьте устройства через Этап 1 (Инвентаризация)")
        return
    
    print(f"\nЗагружено устройств: {len(inventory_manager.infrastructure['devices'])}")
    
    # Создаем планировщик мониторинга
    planner = MonitoringPlanner(inventory_manager.infrastructure)
    
    # Анализируем инфраструктуру
    recommendations = planner.analyze_infrastructure()
    
    # Показываем краткое содержание
    planner.print_summary()
    
    print("\n" + "="*80)
    print("АНАЛИЗ ЗАВЕРШЕН!")
    print("Для получения детального отчета выберите пункт 10 в главном меню")
    print("="*80)

def main():
    """Основная функция программы"""
    try:
        show_banner()
        main_menu()
    except KeyboardInterrupt:
        print("\nПрограмма прервана пользователем")
        sys.exit(0)
    except Exception as e:
        print(f"Ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()