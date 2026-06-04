# MicroPKI

**MicroPKI** — это минималистичный инструмент инфраструктуры открытых ключей (PKI) на Python, предназначенный для создания и управления собственными центрами сертификации (CA). Проект реализует безопасную генерацию ключей, создание самоподписанных сертификатов X.509 v3 и аудит операций.

##  Установка
 ```bash
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
 ```
### Требования
- Python 3.8 или выше
- Менеджер пакетов `pip`

### Использование
Инициализация корневого CA (Root CA)
Команда ca init создает новую инфраструктуру PKI в указанной директории.
Пример 1: RSA ключ (по умолчанию)
 ```bash
# Создайте файл с паролем (не храните его в репозитории!)
echo "RootPass123" > pki/secrets/root.pass
echo "IntPass123" > pki/secrets/int.pass

# Инициализируем базу данных
python -m micropki.cli db init --db-path pki/micropki.db

# Root CA
python -m micropki.cli ca init --subject "/CN=My Root CA,O=MyOrg" --passphrase-file pki/secrets/root.pass --out-dir pki --db-path pki/micropki.db

# Intermediate CA
python -m micropki.cli ca issue-intermediate --root-cert pki/certs/ca.cert.pem --root-key pki/private/ca.key.pem --root-pass-file pki/secrets/root.pass --subject "/CN=My Intermediate CA,O=MyOrg" --passphrase-file pki/secrets/int.pass --out-dir pki --db-path pki/micropki.db
 ```
## Выпуск конечного сертификата
```bash
python -m micropki.cli ca issue-cert --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file pki/secrets/int.pass --template server --subject "/CN=myservice.local,O=MyOrg" --san dns:myservice.local --out-dir pki/issued --db-path pki/micropki.db
```

## Инициализация корневого ЦС
```bash
python -m micropki.cli ca init --subject "/CN=Root CA,O=Organization" --key-type rsa --key-size 4096 --passphrase-file pki/secrets/root.pass --out-dir pki --validity-days 3650 --db-path pki/micropki.db
# Просмотр информации о сертификате
openssl x509 -in pki/certs/ca.cert.pem -text -noout
Пример 2: ECC ключ (кривая P-384)
```
## Выпуск Intermediate CA

 ```bash
python -m micropki.cli ca issue-intermediate --root-cert pki/certs/ca.cert.pem --root-key pki/private/ca.key.pem --root-pass-file pki/secrets/root.pass --subject "/CN=Intermediate CA,O=Organization" --key-type rsa --key-size 4096 --passphrase-file pki/secrets/int.pass --out-dir pki --validity-days 1825 --pathlen 0 --db-path pki/micropki.db
 ```
 ## Выпуск конечного сертификата по шаблону
  ```bash
# Серверный сертификат
python -m micropki.cli ca issue-cert --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file pki/secrets/int.pass --template server --subject "/CN=web.example.com,O=Org" --san dns:web.example.com --san dns:www.example.com --san ip:192.168.1.100 --out-dir pki/issued --validity-days 365 --db-path pki/micropki.db

# Клиентский сертификат
python -m micropki.cli ca issue-cert --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file pki/secrets/int.pass --template client --subject "/CN=user@example.com,O=Org" --san email:user@example.com --out-dir pki/issued --db-path pki/micropki.db

# Сертификат для подписи кода
python -m micropki.cli ca issue-cert --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file pki/secrets/int.pass --template code_signing --subject "/CN=CodeSigner,O=Org" --out-dir pki/issued --db-path pki/micropki.db
  ```
## Управление сертификатами в БД
 ```bash
# Список всех сертификатов
python -m micropki.cli ca list-certs --db-path pki/micropki.db --format table

# Фильтрация по статусу
python -m micropki.cli ca list-certs --db-path pki/micropki.db --status valid --format json

# Просмотр конкретного сертификата по серийному номеру
python -m micropki.cli ca show-cert ABC123DEF456 --db-path pki/micropki.db
 ```
## Запуск HTTP-репозитория
 ```bash
 # Базовый запуск
python -m micropki.cli repo serve --host 127.0.0.1 --port 8080 --db-path pki/micropki.db --cert-dir pki/certs

# С rate limiting (Sprint 7)
python -m micropki.cli repo serve --port 8080 --db-path pki/micropki.db --cert-dir pki/certs --rate-limit 10 --rate-burst 20
  ```
  Примеры запросов
  ```bash
# Получить сертификат
curl http://localhost:8080/certificate/6A1B5538CFD057BE

# Получить Intermediate CA
curl http://localhost:8080/ca/intermediate

# Получить CRL
curl -O http://localhost:8080/crl?ca=intermediate

# Отправить CSR и получить сертификат
curl -X POST -H "Content-Type: application/x-pem-file" --data-binary @request.csr.pem "http://localhost:8080/request-cert?template=server" -o issued.cert.pem
```
## Отзыв сертификата
  ```bash
 # Отзыв по серийному номеру
python -m micropki.cli ca revoke ABC123DEF456 --reason keyCompromise --db-path pki/micropki.db

# Доступные причины отзыва:
# unspecified, keyCompromise, cACompromise, affiliationChanged,
# superseded, cessationOfOperation, certificateHold,
# removeFromCRL, privilegeWithdrawn, aACompromise
  ```
 ## Генерация CRL
 ```bash
# Для Intermediate CA
python -m micropki.cli ca gen-crl --ca intermediate --ca-pass-file pki/secrets/int.pass --next-update 7 --out-dir pki --db-path pki/micropki.db

# Для Root CA
python -m micropki.cli ca gen-crl --ca root --root-pass-file pki/secrets/root.pass --next-update 30 --out-dir pki --db-path pki/micropki.db
 ```
 Проверка CRL через OpenSSL
 ```bash
# Просмотр содержимого CRL
openssl crl -in pki/crl/intermediate.crl.pem -text -noout

# Проверка сертификата против CRL
openssl verify -crl_check -CAfile pki/certs/ca.cert.pem -CRLfile pki/crl/intermediate.crl.pem pki/issued/cert.pem
 ```
 ## Выпуск сертификата для OCSP-респондера
 ```bash
python -m micropki.cli ca issue-ocsp-cert --ca-cert pki/certs/intermediate.cert.pem --ca-key pki/private/intermediate.key.pem --ca-pass-file pki/secrets/int.pass --subject "CN=OCSP Responder,O=Organization" --key-type rsa --key-size 2048 --san uri:http://ocsp.example.com --out-dir pki/ocsp --validity-days 365 --db-path pki/micropki.db
 ```
## Запуск OCSP-респондера
 ```bash
python -m micropki.cli ocsp serve --host 127.0.0.1 --port 8081 --db-path pki/micropki.db --ca-cert pki/certs/intermediate.cert.pem --responder-cert pki/ocsp/ocsp.cert.pem --responder-key pki/ocsp/ocsp.key.pem --cache-ttl 3600

openssl ocsp -issuer pki/certs/intermediate.cert.pem -cert pki/issued/cert.pem -url http://localhost:8081 -text
 ```
 ### Клиентские инструменты
 ## Генерация CSR
 ```bash
python -m micropki.cli client gen-csr --subject "/CN=app.example.com,O=Organization" --key-type rsa --key-size 2048 --san dns:app.example.com --san dns:*.app.example.com --out-key pki/client.key.pem --out-csr pki/client.csr.pem
 ```
## Запрос сертификата через API
 ```bash
python -m micropki.cli client request-cert --csr pki/client.csr.pem --template server --ca-url http://localhost:8080 --out-cert pki/client.cert.pem
 ```
 ## Валидация цепочки сертификатов
  ```bash
# Базовая проверка (подписи + сроки)
python -m micropki.cli client validate --cert pki/client.cert.pem --untrusted pki/certs/intermediate.cert.pem --trusted pki/certs/ca.cert.pem --mode chain

# Полная проверка (с проверкой отзыва)
python -m micropki.cli client validate --cert pki/client.cert.pem --untrusted pki/certs/intermediate.cert.pem --trusted pki/certs/ca.cert.pem --crl pki/crl/intermediate.crl.pem --ocsp-url http://localhost:8081 --mode full
  ```
  ## Проверка статуса отзыва
  ```bash
# Только через OCSP
python -m micropki.cli client check-status --cert pki/client.cert.pem --ca-cert pki/certs/intermediate.cert.pem --ocsp-url http://localhost:8081

# Только через CRL
python -m micropki.cli client check-status --cert pki/client.cert.pem --ca-cert pki/certs/intermediate.cert.pem --crl pki/crl/intermediate.crl.pem

# Авто-переключение: OCSP first, fallback to CRL
python -m micropki.cli client check-status --cert pki/client.cert.pem --ca-cert pki/certs/intermediate.cert.pem --ocsp-url http://localhost:8081 --crl pki/crl/intermediate.crl.pem
  ```
  ## Политики безопасности
  ```bash
# ❌ Срок действия превышен
python -m micropki.cli ca issue-cert ... --validity-days 400
# Ошибка: Validity 400 days > max 365 days for end_entity

# ❌ Слабый ключ
openssl genrsa -out weak.key 1024
python -m micropki.cli ca issue-cert ... --csr weak.csr
# Ошибка: RSA key size 1024 < 2048 bits for end_entity

# ❌ Запрещённый SAN для шаблона
python -m micropki.cli ca issue-cert --template code_signing --san email:dev@example.com
# Ошибка: SAN type 'email' forbidden for template 'code_signing'
  ``` 
 ## Аудит с криптографической целостностью
 ```bash
# Все события выпуска
python -m micropki.cli audit query --operation issue_certificate --format table

# Только ошибки за последние 24 часа
python -m micropki.cli audit query --level ERROR --from 2024-01-01T00:00:00Z --format json

# Фильтр по серийному номеру
python -m micropki.cli audit query --serial ABC123 --format csv

# Верификация целостности при запросе
python -m micropki.cli audit query --operation issue_certificate --verify

# Полная проверка хеш-цепочки
python -m micropki.cli audit verify --log-file pki/audit/audit.log --chain-file pki/audit/chain.dat
 ```
 Тест обнаружения подделки
```bash
# 1. Создаём бэкап
Copy-Item pki/audit/audit.log pki/audit/audit.log.bak

# 2. Повреждаем лог
"X" | Out-File -Append -FilePath pki/audit/audit.log -Encoding ascii

# 3. Проверяем целостность
python -m micropki.cli audit verify --log-file pki/audit/audit.log
# Ожидаем: ✗ AUDIT LOG TAMPERING DETECTED

# 4. Восстанавливаем лог
Move-Item pki/audit/audit.log.bak pki/audit/audit.log -Force
```
Certificate Transparency (симуляция)
```bash
# Проверка наличия сертификата в логе
python -m micropki.cli audit ct-verify --serial ABC123DEF456 --ct-log pki/audit/ct.log
```
Симуляция компрометации ключа
```bash
# Отзыв сертификата с причиной keyCompromise + запись в БД
python -m micropki.cli ca compromise --cert pki/issued/cert.pem --reason keyCompromise --force --db-path pki/micropki.db --audit-log pki/audit/audit.log

# Попытка выпустить сертификат с скомпрометированным ключом
python -m micropki.cli ca issue-cert ... --csr compromised.csr
# Ошибка: Policy violation: CSR uses a compromised public key

# Запуск репозитория с ограничением 10 запросов/сек, всплеск 20
python -m micropki.cli repo serve --port 8080 --rate-limit 10 --rate-burst 20 --db-path pki/micropki.db --cert-dir pki/certs
```
### Структура 
 ```bash
microPKI/
├── micropki/
│   ├── __init__.py
│   ├── cli.py                 # Точка входа CLI
│   ├── ca.py                  # Логика CA (выпуск, отзыв)
│   ├── database.py            # Работа с SQLite
│   ├── crypto_utils.py        # Утилиты криптографии
│   ├── templates.py           # Шаблоны сертификатов
│   ├── serial.py              # Генерация серийных номеров
│   ├── crl.py                 # Генерация CRL
│   ├── ocsp.py                # Обработка OCSP-запросов
│   ├── ocsp_responder.py      # HTTP-сервер для OCSP
│   ├── repository.py          # HTTP-репозиторий сертификатов
│   ├── client_tools.py        # Клиентские команды (Sprint 6)
│   ├── chain.py               # Валидация цепочек
│   ├── revocation_check.py    # Проверка статуса (OCSP/CRL)
│   ├── audit.py               # Аудит с хеш-цепочкой (Sprint 7)
│   ├── policy.py              # Политики безопасности (Sprint 7)
│   ├── ratelimit.py           # Rate limiter (Sprint 7)
│   ├── transparency.py        # CT-лог симуляция (Sprint 7)
│   ├── compromise.py          # Симуляция компрометации (Sprint 7)
│   └── logger.py              # Настройка логирования
├── tests/
│   ├── test_sprint3.py        # Автотесты для Спринта 3
│   └── __init__.py
├── pki/                       # Рабочая директория (создаётся при запуске)
│   ├── micropki.db            # База данных
│   ├── private/               # Закрытые ключи (0600)
│   ├── certs/                 # Публичные сертификаты
│   ├── crl/                   # Списки отзыва
│   ├── audit/
│   │   ├── audit.log          # NDJSON-лог с хеш-цепочкой
│   │   ├── chain.dat          # Текущий хеш цепочки
│   │   └── ct.log             # CT-лог (текстовый)
│   ├── issued/                # Выпущенные конечные сертификаты
│   ├── ocsp/                  # Сертификаты и ключи для OCSP
│   └── secrets/               # Файлы с паролями
├── requirements.txt
├── README.md
└── pyproject.toml
 ```
