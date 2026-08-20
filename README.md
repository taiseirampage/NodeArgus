# NodeArgus

> [!WARNING]
> **Только для авторизованного использования.** Сканирование чужих IP-адресов,
> сетей или сервисов без явного письменного разрешения владельца может быть
> незаконным и повлечь гражданскую или уголовную ответственность. Пользователь
> обязан получить разрешение и согласовать Rules of Engagement до запуска
> NodeArgus. Автор и сопровождающие проекта не несут ответственности за
> неправомерное, неосторожное или вредоносное использование инструмента.

NodeArgus — асинхронный инструмент инвентаризации сети, анализа сервисов,
визуализации топологии и поиска уязвимостей. Он объединяет Masscan, Nmap и
Nuclei, сохраняет результаты в PostgreSQL и отображает их в React/D3.js.

NodeArgus предназначен для:

- аудита собственных сетей и инфраструктуры;
- согласованных penetration test и vulnerability assessment;
- учебных стендов и лабораторий;
- инвентаризации разрешённых внешних активов.

## Архитектура

```mermaid
flowchart LR
    U[User] --> UI[React UI]
    UI --> API[FastAPI API]
    API --> C[Celery task]
    C --> R[(Redis Queue)]
    R --> W[Celery Worker]
    W --> M[Masscan]
    W --> N[Nmap]
    W --> V[Nuclei]
    W --> DB[(PostgreSQL)]
    API --> DB
    DB --> API
```

Основной поток сканирования:

1. Masscan быстро находит доступные TCP-порты.
2. Celery передаёт цель worker-процессу.
3. Nmap выполняет детальное сканирование сервисов, OS fingerprinting, NSE и
   traceroute.
4. Nuclei запускается отдельно для выбранного IP и кэширует результаты на 24
   часа.
5. Результаты сохраняются в PostgreSQL и доступны через API и граф.

## Возможности

- Валидация IP, CIDR и списков целей до запуска сканеров.
- Безопасные Python-обёртки для Masscan, Nmap и Nuclei без shell-конкатенации
  пользовательского ввода.
- PostgreSQL `inet` для IP-адресов и вычисление `same_subnet` на лету.
- GeoIP через локальную MaxMind GeoLite2-City базу.
- Сохранение сервисов, NSE-результатов, OS detection и traceroute hops.
- D3.js-граф с накоплением узлов, zoom/pan и traceroute-цепочками.
- Асинхронные Celery-задачи и polling статуса.
- Nuclei-кэширование, timeout, partial results и отмена задачи.
- HTTP/SOCKS5 proxy и stealth mode для Nuclei. Tor-режим не поддерживается.

## Требования

- Linux рекомендуется для полного доступа Nmap к RAW sockets.
- Docker Engine и Docker Compose v2.
- Git.
- Не менее 2 CPU и 4 GB RAM для небольших тестовых запусков.
- Доступ к PostgreSQL/Redis-портам только из доверенной локальной сети.
- Локальная база MaxMind GeoLite2-City для геолокации.
- Письменное разрешение на каждую внешнюю цель.

## Quick Start

### 1. Клонирование

```bash
git clone https://github.com/taiseirampage/NodeArgus.git
cd NodeArgus
```

### 2. Настройка окружения

```bash
cp .env.example .env
```

Откройте `.env` и задайте собственные значения. Пароли и ключи нельзя
коммитить в Git:

```env
POSTGRES_USER=nodeargus
POSTGRES_PASSWORD=replace-with-a-long-random-password
POSTGRES_DB=nodeargus
POSTGRES_URL=postgresql://nodeargus:replace-with-a-long-random-password@localhost:5432/nodeargus
POSTGRES_ASYNC_URL=postgresql+asyncpg://nodeargus:replace-with-a-long-random-password@localhost:5432/nodeargus
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
GEOIP_DB_PATH=data/GeoLite2-City.mmdb
GEOIP_LICENSE_KEY=
GEOIP_AUTO_UPDATE=false
```

Получите GeoLite2-City у MaxMind и положите файл в `data/`, либо выполните:

```bash
python backend/scripts/download_geoip.py --license-key "$GEOIP_LICENSE_KEY"
```

### 3. Запуск инфраструктуры и миграций

```bash
docker compose up -d postgres redis
docker compose run --rm backend alembic upgrade head
docker compose up -d --build backend celery_worker
```

Проверка состояния:

```bash
docker compose ps
curl http://localhost:8000/health
docker compose logs --tail=50 celery_worker
```

Backend доступен на `http://localhost:8000`. Swagger UI: `http://localhost:8000/docs`.

### 4. Запуск frontend в development-режиме

```bash
cd frontend
npm install
npm run dev
```

Откройте адрес, который напечатает Vite, обычно `http://localhost:5173`.

Production-проверка frontend:

```bash
npm run build
npm test -- --run
```

## Использование

### Через веб-интерфейс

1. Откройте frontend.
2. Введите разрешённый IP, CIDR или список IP.
3. Нажмите запуск сканирования.
4. Дождитесь завершения Celery-задачи.
5. Выберите узел на графе для просмотра портов, ОС, GeoIP, NSE и traceroute.
6. Для vulnerability scan откройте NodeDetailsPanel и запустите Nuclei.
7. При необходимости включите Stealth Mode или отмените выполняющуюся задачу.

Сканер может создавать заметный сетевой шум, запускать NSE-запросы и
вызывать срабатывания IDS/IPS. Запускать его следует только в согласованное
окно тестирования.

### Через API

Запуск обычного сканирования:

```bash
curl -X POST http://localhost:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"192.0.2.10"}'
```

Проверка задачи:

```bash
curl http://localhost:8000/scan/<task_id>
```

Запуск vulnerability scan:

```bash
curl -X POST \
  'http://localhost:8000/vuln/192.0.2.10?force=true&use_stealth_mode=true'
```

Проверка статуса:

```bash
curl http://localhost:8000/vuln/192.0.2.10/<task_id>
```

Последние сохранённые результаты:

```bash
curl http://localhost:8000/vuln/192.0.2.10/latest
```

Отмена выполняющегося vulnerability scan:

```bash
curl -X POST \
  http://localhost:8000/vuln/192.0.2.10/<task_id>/cancel
```

## Как читать отчёты NodeArgus

Результат сканирования описывает наблюдаемое поведение сети, а не абсолютную
истину о целевой системе. Отсутствие ответа также является важным результатом.

### Состояния портов

- `open` — порт ответил и доступен с точки сканирования.
- `closed` — хост доступен, но на этом порту нет принимающего сервиса.
- `filtered` — firewall или сетевой фильтр не позволил определить состояние.
  Это не означает, что порт закрыт.
- `unknown` — инструмент получил недостаточно данных для классификации.

`filtered` — это не ошибка NodeArgus. Например, firewall может молча удалять
SYN-пакеты или ICMP-ответы. В таком случае повторное сканирование тем же
методом не обязательно даст дополнительную информацию.

### OS Detection

Если Nmap не получил нужный fingerprint, NodeArgus показывает:

```text
Unknown (Filtered)
```

Типичные причины:

- фильтрация закрытых TCP/UDP probes;
- нормализация TCP-пакетов firewall;
- отсутствие достаточного количества открытых и закрытых портов;
- облачный security group или perimeter firewall;
- отсутствие RAW socket-доступа на машине сканирования.

`--osscan-guess` не может восстановить ответы, которые не пришли. Поэтому
`Unknown (Filtered)` профессиональнее, чем неподтверждённая догадка об ОС.
Для проверки используйте сервисные версии, баннеры, CPE и данные владельца
системы.

### Traceroute

- `0 hops` или `1 hop` может быть нормой для локального сегмента, VPN,
  cloud overlay или защищённой топологии.
- `*` и пропущенные hops означают, что промежуточный маршрутизатор не ответил.
- Многие провайдеры и облачные сети фильтруют ICMP `Time Exceeded`.
- Traceroute не показывает полный физический путь при такой фильтрации.

NodeArgus не создаёт фиктивные узлы для неизвестных hops и показывает сообщение
о локальном сегменте или скрытой топологии.

### Уязвимости и false positives

Nuclei finding — это сигнал для проверки, а не автоматическое доказательство
компрометации. Для ручной верификации:

1. Проверьте, что `matched_at` действительно относится к разрешённому активу.
2. Сопоставьте сервис, версию и endpoint с данными Nmap.
3. Изучите template ID, CVE, severity и описание шаблона.
4. Сверьте CVE с официальным advisory производителя и условиями уязвимости.
5. Повторите безопасную проверку в тестовой среде или согласованным
   неразрушающим запросом.
6. Не выполняйте exploit-проверки на production без отдельного разрешения.

Особое внимание уделяйте banner-based findings, старым версиям без проверки
конфигурации и результатам через reverse proxy/WAF. Они чаще требуют ручной
валидации.

## Rules of Engagement

Перед запуском согласуйте и сохраните:

- владельца инфраструктуры и письменное разрешение;
- точный список IP, CIDR, доменов и исключений;
- разрешённые техники: port scan, OS detection, NSE, traceroute, Nuclei;
- временное окно и допустимую интенсивность запросов;
- контакт для немедленной остановки теста;
- правила обработки findings, логов и персональных данных;
- критерии остановки при нагрузке, аварии или срабатывании защиты.

Никогда не сканируйте случайные публичные адреса, найденные в интернете.
Примеры документации в этом README используют TEST-NET диапазоны или должны
быть заменены на ваши авторизованные цели.

## Риски и ограничения

- Активное сканирование может быть воспринято как атака и вызвать блокировку.
- NSE и Nuclei создают дополнительный трафик и могут нагрузить сервис.
- OS Detection и traceroute зависят от firewall, NAT, облачных политик и
  возможностей провайдера.
- GeoIP является приблизительным и не определяет физическое местоположение
  устройства.
- Nuclei findings требуют ручной верификации.
- В текущем Compose-профиле worker получает `NET_RAW` и `NET_ADMIN`; это
  повышенные права, необходимые для сетевого сканирования.
- PostgreSQL, Redis и API не следует публиковать в интернет без firewall,
  аутентификации и дополнительного hardening.
- Результаты сканирования могут содержать чувствительные IP, баннеры и CVE;
  ограничьте доступ к БД, Redis, логам и резервным копиям.

## Основные API

| Метод | Endpoint | Назначение |
|---|---|---|
| `POST` | `/scan` | Поставить сетевое сканирование в очередь |
| `GET` | `/scan/{task_id}` | Получить статус сетевого сканирования |
| `GET` | `/ip/{ip}` | Получить детали IP и портов |
| `GET` | `/graph/{ip}` | Получить узлы и связи графа |
| `POST` | `/vuln/{ip}` | Поставить Nuclei scan в очередь |
| `GET` | `/vuln/{ip}/{task_id}` | Получить статус Nuclei scan |
| `GET` | `/vuln/{ip}/latest` | Получить кэшированные findings |
| `POST` | `/vuln/{ip}/{task_id}/cancel` | Отменить Nuclei scan |

## Хранение данных

- PostgreSQL хранит IP в нативном типе `inet`.
- Координаты GeoIP хранятся как `float`; PostGIS не требуется.
- Порты сохраняют номер, протокол, сервис, banner и состояние.
- NSE-вывод и traceroute сохраняются в JSON-полях IP.
- Связи `same_subnet` не записываются в `links`, а вычисляются SQL-операторами
  PostgreSQL на лету.
- Traceroute hops сохраняются как отдельные узлы и связи `traceroute_hop`.
- Nuclei findings кэшируются на 24 часа, если не указан `force=true`.

## GeoIP Setup

NodeArgus использует локальную MaxMind GeoLite2-City и не обращается к внешнему
GeoIP API для каждого сканирования.

1. Создайте бесплатную учётную запись на
   [MaxMind](https://www.maxmind.com/en/geolite2/signup).
2. Создайте license key для GeoLite2.
3. Задайте `GEOIP_LICENSE_KEY` в `.env`.
4. Скачайте базу:

```bash
python backend/scripts/download_geoip.py --license-key "$GEOIP_LICENSE_KEY"
```

Или вручную положите `GeoLite2-City.mmdb` в `data/` и задайте:

```env
GEOIP_DB_PATH=data/GeoLite2-City.mmdb
```

## Troubleshooting

Проверить контейнеры:

```bash
docker compose ps
docker compose logs --tail=100 backend celery_worker
```

Проверить миграции:

```bash
docker compose run --rm backend alembic current
docker compose run --rm backend alembic upgrade head
```

Если порт имеет состояние `filtered`, сначала проверьте Rules of Engagement,
firewall и разрешённость probes. Не интерпретируйте это как `closed`.

Если OS равна `Unknown (Filtered)` или traceroute содержит `0 hops`, проверьте
локальные capabilities worker и сетевую политику цели. Это ожидаемый результат
для многих облачных и защищённых периметров.

## Разработка и тесты

Backend:

```bash
cd backend
PYTHONPATH=. pytest -q
```

Frontend:

```bash
cd frontend
npm test -- --run
npm run build
npm run lint
```

## Лицензирование и ответственное использование

Перед публикацией проекта уточните лицензию в отдельном файле `LICENSE`.
Лицензия на код не даёт разрешения на сканирование чужих систем. Разрешение,
Rules of Engagement и местное законодательство имеют приоритет над любыми
примерами команд в этом документе.
