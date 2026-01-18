"""
Модуль для расчета индекса внедрения Zero Trust (RZT)
"""

from typing import Dict, List, Tuple
from datetime import datetime

class ZTICalculator:
    """Калькулятор индекса внедрения Zero Trust"""
    
    @staticmethod
    def calculate_initial_zti(devices: List[Dict]) -> Dict:
        """Рассчитать исходный RZT до внедрения рекомендаций"""
        total_devices = len(devices)
        if total_devices == 0:
            return {
                "zti_score": 0,
                "zti_percentage": 0,
                "components": {
                    "encryption": 0,
                    "import_devices": 100,
                    "segmentation": 0,
                    "mfa": 0
                },
                "recommendation": "Нет данных об устройствах"
            }
        
        # 1. Доля устройств с шифрованием (E)
        encrypted_count = sum(1 for d in devices if d.get("encryption", False))
        encryption_percentage = (encrypted_count / total_devices) * 100
        
        # 2. Доля импортных устройств (IM)
        domestic_manufacturers = ["Овен", "Элвис-Нео", "Ростелеком", "Болид", "Киберлок", "Рутокен", "КриптоПро"]
        import_count = sum(1 for d in devices 
                          if d.get("manufacturer") not in domestic_manufacturers)
        import_percentage = (import_count / total_devices) * 100
        
        # 3. Уровень сегментации сети (SE) - изначально 0
        segmentation_percentage = 0
        
        # 4. Уровень многофакторной аутентификации (MFA) - изначально 0
        mfa_percentage = 0
        
        # Расчет RZT по формуле: (0.3*SE + 0.3*MFA + 0.2*E + 0.2*(100%-IM))/100
        zti_score = (
            0.3 * segmentation_percentage +
            0.3 * mfa_percentage +
            0.2 * encryption_percentage +
            0.2 * (100 - import_percentage)
        ) / 100
        
        return {
            "zti_score": zti_score,
            "zti_percentage": zti_score * 100,
            "components": {
                "encryption": encryption_percentage,
                "import_devices": import_percentage,
                "segmentation": segmentation_percentage,
                "mfa": mfa_percentage
            },
            "recommendation": "Исходное состояние"
        }
    
    @staticmethod
    def calculate_stage_zti(
        devices: List[Dict],
        stage: str,
        stage_data: Dict = None
    ) -> Dict:
        """Рассчитать RZT после конкретного этапа"""
        total_devices = len(devices)
        
        # Базовые компоненты
        domestic_manufacturers = ["Овен", "Элвис-Нео", "Ростелеком", "Болид", "Киберлок", "Рутокен", "КриптоПро"]
        
        encrypted_count = sum(1 for d in devices if d.get("encryption", False))
        encryption_percentage = (encrypted_count / total_devices) * 100
        
        import_count = sum(1 for d in devices 
                          if d.get("manufacturer") not in domestic_manufacturers)
        import_percentage = (import_count / total_devices) * 100
        
        # Значения по умолчанию
        segmentation_percentage = 0
        mfa_percentage = 0
        
        # Обновляем значения в зависимости от этапа
        if stage == "encryption" and stage_data:
            # После этапа 2: шифрование
            # Предполагаем, что будут внедрены все рекомендации
            encryption_percentage = min(100, encryption_percentage + 40)  # +40% после внедрения
            
        elif stage == "segmentation" and stage_data:
            # После этапа 3: сегментация
            segmentation_percentage = 70  # Средний уровень сегментации после внедрения
            
            # Уменьшаем долю импортных устройств за счет замены
            import_percentage = max(0, import_percentage - 20)
            
        elif stage == "mfa" and stage_data:
            # После этапа 4: MFA
            mfa_percentage = 80  # Высокий уровень MFA после внедрения
            
            # Уменьшаем долю импортных устройств
            import_percentage = max(0, import_percentage - 10)
            
        elif stage == "monitoring" and stage_data:
            # После этапа 5: мониторинг
            # Повышаем все показатели за счет улучшения безопасности
            encryption_percentage = min(100, encryption_percentage + 10)
            segmentation_percentage = 85
            mfa_percentage = 90
            import_percentage = max(0, import_percentage - 5)
        
        # Расчет RZT
        zti_score = (
            0.3 * segmentation_percentage +
            0.3 * mfa_percentage +
            0.2 * encryption_percentage +
            0.2 * (100 - import_percentage)
        ) / 100
        
        return {
            "zti_score": zti_score,
            "zti_percentage": zti_score * 100,
            "components": {
                "encryption": encryption_percentage,
                "import_devices": import_percentage,
                "segmentation": segmentation_percentage,
                "mfa": mfa_percentage
            },
            "stage": stage,
            "timestamp": datetime.now().isoformat()
        }
    
    @staticmethod
    def calculate_final_zti(devices: List[Dict]) -> Dict:
        """Рассчитать итоговый RZT после всех рекомендаций"""
        total_devices = len(devices)
        
        # Оптимистичный сценарий после всех этапов
        domestic_manufacturers = ["Овен", "Элвис-Нео", "Ростелеком", "Болид", "Киберлок", "Рутокен", "КриптоПро"]
        
        # После всех этапов:
        # 1. Шифрование
        encrypted_count = sum(1 for d in devices if d.get("encryption", False))
        encryption_percentage = min(95, round((encrypted_count + sum(1 for d in devices if d.get("critical", True)) / total_devices) * 100, 2))

        # 2. Сегментация
        segmentation_count = sum(1 for d in devices if d.get("encryption", False))
        segmentation_percentage = min(90, round(segmentation_count + 3 + sum(1 for d in devices if d.get("uses_domestic_algorithm", False))*2 + sum(1 for d in devices if d.get("critical", True)*2) / total_devices * 100, 2) + 10)

        # 3. MFA
        mfa_count = sum(1 for d in devices if d.get("encryption", False))
        # Убираем нетребующие MFA механизмы
        # Округляем до целого числа устройств
        mfa_percentage = min(100, (round((mfa_count + round(total_devices*0.2,0) / total_devices) + sum(1 for d in devices if d.get("critical", True))* 2 + sum(1 for d in devices if d.get("uses_domestic_algorithm", False)), 2)) + 30)

        # 4. Доля импортных устройств
        import_count = sum(1 for d in devices 
                        if d.get("manufacturer") not in domestic_manufacturers)
        import_percentage = max(0, round(((max(import_count*0.5 - 3,0 ))/ total_devices) * 100, 2))
        
        # Расчет итогового RZT
        zti_score = (
            0.3 * segmentation_percentage +
            0.3 * mfa_percentage +
            0.2 * encryption_percentage +
            0.2 * (100 - import_percentage)
        ) / 100
        
        return {
            "zti_score": zti_score,
            "zti_percentage": zti_score * 100,
            "components": {
                "encryption": encryption_percentage,
                "import_devices": import_percentage,
                "segmentation": segmentation_percentage,
                "mfa": mfa_percentage
            },
            "assessment": ZTICalculator._get_zti_assessment(zti_score),
            "recommendations": ZTICalculator._get_final_recommendations(zti_score)
        }
    
    @staticmethod
    def _get_zti_assessment(zti_score: float) -> str:
        """Получить оценку уровня RZT"""
        if zti_score >= 0.8:
            return "ОТЛИЧНО - полное соответствие модели Zero Trust"
        elif zti_score >= 0.7:
            return "ХОРОШО - высокий уровень безопасности"
        elif zti_score >= 0.6:
            return "УДОВЛЕТВОРИТЕЛЬНО - базовый уровень Zero Trust"
        elif zti_score >= 0.5:
            return "НИЗКИЙ - требуются значительные улучшения"
        else:
            return "КРИТИЧЕСКИЙ - срочное внедрение мер безопасности"
    
    @staticmethod
    def _get_final_recommendations(zti_score: float) -> List[str]:
        """Получить рекомендации по итоговому RZT"""
        if zti_score >= 0.8:
            return [
                "Поддерживайте текущий уровень безопасности",
                "Регулярно проводите аудит и тестирование на проникновение",
                "Обновляйте политики безопасности в соответствии с новыми угрозами"
            ]
        elif zti_score >= 0.7:
            return [
                "Увеличьте долю отечественного оборудования",
                "Внедрите MFA на всех административных интерфейсах",
                "Усилите мониторинг аномальной активности"
            ]
        else:
            return [
                "Приоритетно внедрите шифрование на критических устройствах",
                "Реализуйте сегментацию сети для изоляции рисков",
                "Начните внедрение MFA с наиболее критичных систем",
                "Разработайте план замены импортного оборудования"
            ]
    
    @staticmethod
    def generate_zti_report(initial_zti: Dict, stage_zti_list: List[Dict], final_zti: Dict) -> str:
        """Сгенерировать отчет по динамике RZT"""
        report = []
        report.append("="*80)
        report.append("АНАЛИЗ ИНДЕКСА ВНЕДРЕНИЯ ZERO TRUST (RZT)")
        report.append("="*80)
        
        report.append(f"\nИСХОДНЫЙ ИНДЕКС RZT:")
        report.append(f"  RZT: {initial_zti['zti_percentage']:.1f}% ({initial_zti['zti_score']:.3f})")
        report.append(f"  Компоненты:")
        report.append(f"    • Шифрование (E): {initial_zti['components']['encryption']:.1f}%")
        report.append(f"    • Импортные устройства (IM): {initial_zti['components']['import_devices']:.1f}%")
        report.append(f"    • Сегментация (SE): {initial_zti['components']['segmentation']:.1f}%")
        report.append(f"    • MFA: {initial_zti['components']['mfa']:.1f}%")

        report.append(f"\nИТОГОВЫЙ ИНДЕКС RZT (после всех рекомендаций):")
        report.append(f"  RZT: {final_zti['zti_percentage']:.1f}% ({final_zti['zti_score']:.3f})")
        report.append(f"  Оценка: {final_zti['assessment']}")
        
        report.append(f"\nКОМПОНЕНТЫ ИТОГОВОГО RZT:")
        report.append(f"  • Шифрование (E): {final_zti['components']['encryption']:.1f}%")
        report.append(f"  • Импортные устройства (IM): {final_zti['components']['import_devices']:.1f}%")
        report.append(f"  • Сегментация (SE): {final_zti['components']['segmentation']:.1f}%")
        report.append(f"  • MFA: {final_zti['components']['mfa']:.1f}%")
        
        report.append(f"\nОБЩАЯ ДИНАМИКА:")
        report.append(f"  Начальный RZT: {initial_zti['zti_percentage']:.1f}%")
        report.append(f"  Итоговый RZT: {final_zti['zti_percentage']:.1f}%")
        report.append(f"  Рост: +{(final_zti['zti_percentage'] - initial_zti['zti_percentage']):.1f}%")
        report.append(f"  Коэффициент улучшения: {(final_zti['zti_score'] / initial_zti['zti_score']):.2f}x")

                
        report.append(f"\nРЕКОМЕНДАЦИИ:")
        for rec in final_zti.get('recommendations', []):
            report.append(f"  • {rec}")
        
        return "\n".join(report)