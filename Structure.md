ZeroTrustModeller/
│
├── README.md                 # Описание проекта
├── main.py                   # Главный запускаемый файл
├── requirements.txt          # Зависимости
├── config/
│   ├── devices_catalog.json  # Каталог устройств для выбора
│   └── vulnerabilities.json  # База уязвимостей (позже)
│
├── data/
│   └── infrastructure.json   # Текущая инфраструктура пользователя
│
└── modules/
    ├── __init__.py
    ├── inventory.py         # Модуль инвентаризации (этап 1)
    ├── encryption.py        # Модуль шифрования (этап 2)
    ├── segmentation.py      # Модуль сегментации (этап 3)
    ├── mfa.py              # Модуль MFA (этап 4)
    ├── monitoring.py       # Модуль мониторинга (этап 5)
    └── report_generator.py # Генератор отчета