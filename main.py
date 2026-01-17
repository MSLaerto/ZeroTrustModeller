#!/usr/bin/env python3
"""
ZeroTrustModeller - Программа для моделирования внедрения Zero Trust в IoT
"""

import os
import sys

from modules.inventory import InventoryManager
from modules.encryption_planner import EncryptionPlanner
from modules.report_generator import ReportGenerator
from modules.segmentation_planner import SegmentationPlanner  # <-- ДОБАВИТЬ ЭТОТ ИМПОРТ

def show_banner():
    """Показать заголовок программы"""
    print("=" * 60)
    print("ZeroTrustModeller - Моделирование Zero Trust для IoT")
    print("Адаптировано под требования ФСТЭК и российские стандарты")
    print("=" * 60)

def main_menu():
    """Главное меню программы"""
    while True:
        print("\nГЛАВНОЕ МЕНЮ")
        print("1. Инвентаризация устройств (Этап 1)")
        print("2. Анализ шифрования (Этап 2)")
        print("3. Планирование сегментации (Этап 3)")
        print("4. Настройка MFA (Этап 4)")
        print("5. Мониторинг и поддержка (Этап 5)")
        print("6. Сформировать полный отчет (Этапы 1-2)")
        print("7. Сформировать отчет по шифрованию (Этап 2 детально)")
        print("8. Сформировать отчет по сегментации (Этап 3)")
        print("9. Экспорт данных")
        print("0. Выход")
        
        choice = input("\nВыберите действие: ").strip()
        
        if choice == "0":
            if input("Вы уверены, что хотите выйти? (да/нет): ").lower() == "да":
                print("Программа завершена. До свидания!")
                sys.exit(0)
        elif choice == "1":
            # Этап 1: Инвентаризация
            inventory_manager = InventoryManager()
            inventory_manager.run()
        elif choice == "2":
            # Этап 2: Шифрование
            execute_encryption_analysis()
        elif choice == "3":
            # Этап 3: Сегментация
            execute_segmentation_analysis()
        elif choice == "6":
            # Полный отчет (Этапы 1-2)
            execute_full_report()
        elif choice == "7":
            # Детальный отчет по этапу 2
            execute_detailed_encryption_report()
        elif choice == "8":
            # Детальный отчет по этапу 3
            execute_detailed_segmentation_report()
        else:
            print("Функционал в разработке...")

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
    
    # Генерируем и сохраняем отчет
    report_file = planner.save_report_to_file()
    
    print("\n" + "="*80)
    print("АНАЛИЗ ЗАВЕРШЕН!")
    print(f"Детальный отчет по этапу 3 сохранен в: {report_file}")
    print("="*80)
    
    # Предлагаем просмотреть отчет
    if input("\nПоказать краткое содержание отчета? (да/нет) [нет]: ").strip().lower() == "да":
        print("\n" + "="*80)
        report_text = planner.generate_report()
        # Показываем первые 2000 символов
        print(report_text[:2000])
        print("\n... (полный отчет в файле)")

def execute_detailed_segmentation_report():
    """Сформировать детальный отчет по этапу 3"""
    print("\n" + "="*80)
    print("ДЕТАЛЬНЫЙ ОТЧЕТ ПО ЭТАПУ 3 (СЕГМЕНТАЦИЯ СЕТИ)")
    print("="*80)
    
    # Загружаем текущую инфраструктуру
    inventory_manager = InventoryManager()
    
    if not inventory_manager.infrastructure["devices"]:
        print("\nОшибка: Нет устройств для анализа!")
        print("Сначала добавьте устройства через Этап 1 (Инвентаризация)")
        return
    
    # Создаем планировщик сегментации
    planner = SegmentationPlanner(inventory_manager.infrastructure)
    
    # Анализируем инфраструктуру
    recommendations = planner.analyze_infrastructure()
    
    # Сохраняем детальный отчет
    report_file = planner.save_report_to_file("segmentation_detailed_report.txt")
    
    print(f"\nДетальный отчет по этапу 3 сохранен в: {report_file}")
    print("\nСодержание отчета:")
    print("• 3.1. Устранение концепции доверенных зон")
    print("• 3.2. Минимальные привилегии для устройств")
    print("• 3.3. Изолированные сегменты сети")
    print("• 3.4. Изоляция устройств с физическим доступом")
    print("• 3.5. Сквозной контроль трафика")
    print("• Выявленные риски и рекомендации")

# ... остальные функции (execute_encryption_analysis, execute_full_report и т.д.) ...

def main():
    """Основная функция программы"""
    try:
        show_banner()
        main_menu()
    except KeyboardInterrupt:
        print("\nПрограмма прервана пользователя")
        sys.exit(0)
    except Exception as e:
        print(f"Ошибка: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()