# MicroPKI

**MicroPKI** — это минималистичный инструмент инфраструктуры открытых ключей (PKI) на Python, предназначенный для создания и управления собственными центрами сертификации (CA). Проект реализует безопасную генерацию ключей, создание самоподписанных сертификатов X.509 v3 и аудит операций.

## Спринт 1 (Root CA Foundation)

### 🚀 Возможности (Спринт 1)

- **Генерация ключей:** Поддержка алгоритмов RSA (4096 бит) и ECC (NIST P-384).
- **Сертификаты X.509 v3:** Создание самоподписанных корневых сертификатов с критическими расширениями:
  - `BasicConstraints` (CA=TRUE)
  - `KeyUsage` (keyCertSign, cRLSign)
  - `SubjectKeyIdentifier` (SKI) и `AuthorityKeyIdentifier` (AKI)
- **Безопасное хранение:**
  - Шифрование приватных ключей паролем (AES-256-CBC, PKCS#8).
  - Автоматическая установка строгих прав доступа к файлам (chmod 600/700).
  - Защита паролей от попадания в логи.
- **Аудит и политики:**
  - Подробное логирование событий в формате ISO 8601.
  - Автоматическая генерация документа политики (`policy.txt`).
- **CLI интерфейс:** Удобная командная строка с валидацией аргументов.

---

##  Установка

### Требования
- Python 3.8 или выше
- Менеджер пакетов `pip`

### Шаги установки


   ```bash
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   pip install -r requirements.txt
  ```
### Использование
Инициализация корневого CA (Root CA)
Команда ca init создает новую инфраструктуру PKI в указанной директории.
Пример 1: RSA ключ (по умолчанию)
 ```bash
# Создайте файл с паролем (не храните его в репозитории!)
echo "MySuperSecretPassword123" > secrets/ca.pass

# Запуск генерации
python -m micropki.cli ca init --subject "/CN=Demo Root CA,O=MicroPKI,C=US" --key-type rsa --key-size 4096 --passphrase-file ./secrets/ca.pass --out-dir ./pki --validity-days 3650 --log-file ./logs/ca-init.log
 ```
Пример 2: ECC ключ (кривая P-384)
 ```bash
 python -m micropki.cli ca init --subject "CN=ECC Root CA,O=MicroPKI" --key-type ecc --key-size 384 --passphrase-file ./secrets/ca.pass --out-dir ./pki_ecc
 ```
### Структура выходных данных
После успешного выполнения команды в директории --out-dir создается следующая структура:
 ```bash
 pki/
├── private/
│   └── ca.key.pem       # Зашифрованный приватный ключ (Permissions: 600)
├── certs/
│   └── ca.cert.pem      # Открытый сертификат в формате PEM
└── policy.txt           # Документ с политикой и деталями сертификата
 ```
### Тестирование
Запуск автотестов (pytest)
 ```bash
python -m pytest tests/ -v
 ```
Ручная верификация
 ```bash
 python verify_ca.py
 ```
