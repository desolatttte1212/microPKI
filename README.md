# MicroPKI

**MicroPKI** — это минималистичный инструмент инфраструктуры открытых ключей (PKI) на Python, предназначенный для создания и управления собственными центрами сертификации (CA). Проект реализует безопасную генерацию ключей, создание самоподписанных сертификатов X.509 v3 и аудит операций.

## Спринт 2: Иерархическая PKI
Во втором спринте добавлена поддержка многоуровневой инфраструктуры:
Intermediate CA: Создание промежуточного центра сертификации, подписанного корневым (Root CA).
Шаблоны сертификатов: Автоматическая настройка расширений для серверов (server), клиентов (client) и подписи кода (code_signing).
Subject Alternative Name (SAN): Поддержка множественных имен (DNS, IP, Email, URI) в одном сертификате.
Валидация цепочки: Инструменты для проверки доверия от листового сертификата до корня.
### Создание Intermediate CA
Промежуточный центр позволяет изолировать корневой ключ и гибко управлять выпуском сертификатов.
 ```bash
# 1. Создайте пароль для промежуточного центра
echo "IntermediatePass123" > secrets/intermediate.pass

# 2. Сгенерируйте Intermediate CA (подписывается Root CA)
python -m micropki.cli ca issue-intermediate \
    --root-cert ./pki/certs/ca.cert.pem \
    --root-key ./pki/private/ca.key.pem \
    --root-pass-file ./secrets/root.pass \
    --subject "/CN=My Intermediate CA,O=MyCompany" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file ./secrets/intermediate.pass \
    --out-dir ./pki \
    --validity-days 1825 \
    --pathlen 0
 ```
### Выпуск листовых сертификатов (Leaf Certificates)
Используйте шаблон --template для автоматической настройки расширений (Key Usage, Extended Key Usage).
Пример А: Серверный сертификат (HTTPS)
Обязательно требует наличия SAN (DNS или IP).
 ```bash
python -m micropki.cli ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template server \
    --subject "/CN=example.com,O=MyCompany" \
    --san dns:example.com \
    --san dns:www.example.com \
    --san ip:192.168.1.10 \
    --out-dir ./pki/certs/issued \
    --validity-days 365
 ```
Пример Б: Клиентский сертификат (VPN, Auth)
Рекомендуется указывать Email в SAN.
 ```bash
python -m micropki.cli ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template code_signing \
    --subject "/CN=MyCode Signer" \
    --out-dir ./pki/certs/issued
 ```
### Проверка цепочки доверия
 ```bash
python verify_chain.py
 ```
### Запуск тестов
 ```bash
python -m pytest tests/test_sprint2.py -v
 ```
