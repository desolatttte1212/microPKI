# MicroPKI

##  Спринт 3: Управление жизненным циклом и Репозиторий
- ✅ Интеграция с **SQLite** для хранения метаданных сертификатов.
- ✅ Гарантированно уникальные серийные номера (Timestamp + CSPRNG).
- ✅ CLI команды для аудита: список сертификатов, просмотр по серийному номеру.
- ✅ Встроенный **HTTP-сервер (Flask)** для распространения сертификатов и заглушки CRL.
- ✅ Полное покрытие автотестами (`pytest`).

---

## Быстрый старт

### Требования
- Python 3.8+
- Библиотеки: `cryptography`, `flask`, `pytest`, `tabulate`, `requests`.

Установка зависимостей:
```bash
pip install -r requirements.txt
```
### 1. Инициализация системы
Сначала создайте базу данных и корневой центр сертификации (Root CA).
```bash
# Создаем файл с паролем для Root CA
echo "SuperSecretRootPass" > secrets/root.pass

# Инициализируем базу данных
python -m micropki.cli db init --db-path ./pki/micropki.db

# Создаем Root CA
python -m micropki.cli ca init \
    --subject "/CN=My Organization Root CA,O=MyOrg,C=US" \
    --passphrase-file ./secrets/root.pass \
    --out-dir ./pki \
    --db-path ./pki/micropki.db
```

### 2. Создание Intermediate CA
Для безопасности выпуска сертификатов создадим промежуточный центр.
```bash
# Создаем пароль для Intermediate CA
echo "IntermediatePass" > secrets/intermediate.pass

# Выпускаем Intermediate CA (подписываем его Root CA)
python -m micropki.cli ca issue-intermediate \
    --root-cert ./pki/certs/ca.cert.pem \
    --root-key ./pki/private/ca.key.pem \
    --root-pass-file ./secrets/root.pass \
    --subject "/CN=My Organization Intermediate CA,O=MyOrg" \
    --passphrase-file ./secrets/intermediate.pass \
    --out-dir ./pki \
    --db-path ./pki/micropki.db
```
### 3. Выпуск сертификатов
Теперь можно выпускать конечные сертификаты. Они автоматически сохраняются в базу данных.
Пример: Серверный сертификат (HTTPS)
```bash
python -m micropki.cli ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template server \
    --subject "/CN=example.com,O=MyOrg" \
    --san dns:example.com \
    --san dns:www.example.com \
    --san ip:192.168.1.10 \
    --out-dir ./pki/certs/issued \
    --db-path ./pki/micropki.db
```
Пример: Клиентский сертификат
```bash
python -m micropki.cli ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template client \
    --subject "/CN=Alice Smith,EMAIL=alice@myorg.com" \
    --san email:alice@myorg.com \
    --out-dir ./pki/certs/issued \
    --db-path ./pki/micropki.db
```

## Управление и Аудит (CLI)
MicroPKI предоставляет удобные команды для работы с базой данных сертификатов.
Просмотр списка сертификатов
Выводит таблицу всех выпущенных сертификатов.
```bash
python -m micropki.cli ca list-certs --db-path ./pki/micropki.db --format table
```
Поддерживаемые форматы: table, json, csv.
Фильтрация по статусу: --status valid.
Получение сертификата по серийному номеру
Выводит PEM-блок сертификата прямо в консоль.
```bash
python -m micropki.cli ca show-cert <SERIAL_HEX> --db-path ./pki/micropki.db
```
## HTTP Репозиторий
Встроенный веб-сервер позволяет распространять сертификаты по сети (например, для настройки браузеров или системных хранилищ доверия).
Запуск сервера
```bash
python -m micropki.cli repo serve \
    --host 0.0.0.0 \
    --port 8080 \
    --db-path ./pki/micropki.db \
    --cert-dir ./pki/certs
```
Пример запроса через curl:
```bash
# Скачать сертификат по серийному номеру
curl http://localhost:8080/certificate/69C425A77256E66E --output user_cert.pem

# Скачать Root CA
curl http://localhost:8080/ca/root --output root_ca.pem
```
## Тестирование
Проект покрыт интеграционными тестами, которые проверяют весь цикл: от создания БД до работы HTTP-API.
Запуск тестов
```bash
pip install pytest requests tabulate
pytest tests/test_sprint3.py -v -s
```
