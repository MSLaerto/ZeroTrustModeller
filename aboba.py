import matplotlib.pyplot as plt
import numpy as np

# Данные
categories = [
    "умный дом",
    "умный офис\n«Технопарк»",
    "медицинское\nучреждение",
    "объект ЖКХ",
    "логистический центр"
]

initial_rzt = [15.7, 16.6, 12.5, 15.5, 29.0]
final_rzt = [84.5, 87.1, 87.8, 85.8, 86.8]

# Параметры диаграммы
x = np.arange(len(categories))  # позиции групп
total_width = 0.7  # общая ширина на пару столбцов
bar_gap = 0.08     # расстояние между столбцами внутри пары (в долях от 1)
bar_width = (total_width - bar_gap) / 2  # ширина каждого столбца

fig, ax = plt.subplots(figsize=(12, 7))

# Столбцы с расстоянием между ними
bars1 = ax.bar(x - bar_width/2 - bar_gap/2, initial_rzt, bar_width, 
               label='Начальный RZT', color='steelblue', edgecolor='black')
bars2 = ax.bar(x + bar_width/2 + bar_gap/2, final_rzt, bar_width, 
               label='Итоговый RZT', color='darkorange', edgecolor='black')

# Подписи значений над столбцами (начальные)
for bar in bars1:
    height = bar.get_height()
    ax.annotate(f'{height}%',
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 3),
                textcoords="offset points",
                ha='center', va='bottom', fontsize=9, fontweight='bold')

# Подписи значений над столбцами (итоговые)
for bar in bars2:
    height = bar.get_height()
    ax.annotate(f'{height}%',
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 3),
                textcoords="offset points",
                ha='center', va='bottom', fontsize=9, fontweight='bold')

# Оформление
ax.set_ylabel('RZT (%)', fontsize=12)
ax.set_title('Сравнение начального и итогового RZT модельных кейсов', fontsize=14, fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(categories, fontsize=10)
ax.legend(loc='upper left', fontsize=10)
ax.grid(axis='y', linestyle='--', alpha=0.7)
ax.set_ylim(0, 100)

plt.tight_layout()
plt.show()