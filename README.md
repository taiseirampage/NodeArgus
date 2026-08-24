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
Nuclei, сохраняет результаты в PostgreSQL и отображает их на полноэкранной
интерактивной карте мира (Leaflet) с альтернативным D3.js-графом топологии.

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
5. Результаты сохраняются в PostgreSQL и доступны через API, карту мира и граф.

## Возможности

- Валидация IP, CIDR и списков целей до запуска сканеров.
- Безопасные Python-обёртки для Masscan, Nmap и Nuclei без shell-конкатенации
  пользовательского ввода.
- Passive recon субадоменов через Subfinder и расширенная разведка (Subfinder +
  OWASP Amass): поддомены, ASN, CIDR и инвентаризация инфраструктуры.
- PostgreSQL `inet` для IP-адресов и вычисление `same_subnet` на лету.
- GeoIP через локальную MaxMind GeoLite2-City базу.
- Сохранение сервисов, NSE-результатов, OS detection и traceroute hops.
- Полноэкранная карта мира (Leaflet, тайлы CartoDB Dark Matter) как основной
  интерфейс: маркеры GeoIP по severity, кластеризация, поиск по IP с центровкой
  карты и автооткрытием popup.
- Переключатель вида «Карта / Топология»: выбранный вид сохраняется в
  `localStorage` и восстанавливается при перезагрузке.
- D3.js-граф с накоплением узлов, zoom/pan и traceroute-цепочками
  (альтернативный вид).
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

Основной интерфейс — полноэкранная карта мира. Управление собрано в
плавающей панели слева поверх карты:

1. Откройте frontend.
2. В плавающей панели введите разрешённый IP, CIDR, список IP или домен.
3. Выберите режим (Active / Recon / Full) и при необходимости инструменты
   разведки и режим Amass.
4. Нажмите «Сканировать» и следите за статусом задачи в телеметрии справа.
5. Маркеры на карте окрашены по максимальной severity:
   `critical` — красный, `high` — оранжевый, `medium` — жёлтый,
   `low`/`info` — синий, `no_vulns` — зелёный. На больших объёмах маркеры
   кластеризуются.
6. Клик по маркеру открывает popup (IP, страна/город, число портов) и кнопку
   «Подробнее» — она открывает панель деталей узла справа.
7. В панели деталей доступны порты, ОС, GeoIP, NSE, traceroute, web/endpoints
   и запуск Nuclei (vulnerability scan), включая Stealth / WAF Bypass и отмену
   выполняющейся задачи.
8. Поиск в плавающей панели центрирует карту на найденном IP и открывает его
   popup; если актив не найден, показывается уведомление.
9. Переключатель «🗺️ Карта / 🕸️ Топология» в панели показывает D3.js-граф
   топологии как альтернативный вид; выбор сохраняется между сессиями.

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
| `POST` | `/scan` | Поставить сканирование в очередь (включая объединённый recon) |
| `GET` | `/scan/{task_id}/status` | Получить статус и прогресс по инструментам |
| `GET` | `/scan/{task_id}` | Статус (обратная совместимость) |
| `GET` | `/ip/{ip}` | Получить детали IP и портов |
| `GET` | `/graph/{ip}` | Получить узлы и связи графа |
| `GET` | `/map/assets` | Гео-активы для карты мира (кэш 5 минут) |
| `POST` | `/vuln/{ip}` | Поставить Nuclei scan в очередь |
| `GET` | `/vuln/{ip}/{task_id}` | Получить статус Nuclei scan |
| `GET` | `/vuln/{ip}/latest` | Получить кэшированные findings |
| `POST` | `/vuln/{ip}/{task_id}/cancel` | Отменить Nuclei scan |

Пример объединённого recon-запроса:

```bash
curl -X POST http://localhost:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"example.com","scan_type":"recon","recon_tools":["subfinder","amass"],"amass_mode":"passive"}'
```

Если `target` — IP/CIDR, `recon_tools` игнорируется (запускается active scan).
При `scan_type="full"` после recon запускается активное сканирование найденных IP.

## Объединённая разведка (Subfinder + Amass)

`run_unified_recon_task` запускает выбранные инструменты **параллельно** через
`celery.canvas.group`, затем:

1. Собирает все поддомены из Subfinder и Amass.
2. Де-дуплицирует по имени (`set`).
3. Делает DNS-резолвинг каждого уникального поддомена **батчами по 50**.
4. Сохраняет в БД, объединяя источники: найденный обоими инструментами поддомен
   получает `source = "crtsh,subfinder,amass"`.
5. Переносит ASN-атрибуцию Amass в `domains` (`asn`, `cidr`, `org_name`).
6. Возвращает `{total_subdomains, unique_ips, tools_used, asn_info}`.

Прогресс по каждому инструменту доступен через `GET /scan/{task_id}/status`
(поле `progress`).

## Хранение данных

- PostgreSQL хранит IP в нативном типе `inet`.
- Координаты GeoIP хранятся как `float`; PostGIS не требуется.
- `GET /map/assets` возвращает только IP с валидными координатами
  (`lat IS NOT NULL AND lng IS NOT NULL`), числом открытых портов и
  максимальной severity по IP; ответ кэшируется в памяти API на 5 минут.
- Порты сохраняют номер, протокол, сервис, banner и состояние.
- NSE-вывод и traceroute сохраняются в JSON-полях IP.
- Связи `same_subnet` не записываются в `links`, а вычисляются SQL-операторами
  PostgreSQL на лету.
- Traceroute hops сохраняются как отдельные узлы и связи `traceroute_hop`.
- Nuclei findings кэшируются на 24 часа, если не указан `force=true`.
- ASN-атрибуция домена хранится в `domains.asn`/`domains.cidr`/`domains.org_name`,
  а история ASN — в таблице `asn_info` (per-domain история номеров, CIDR, описаний).
- Поддомены, найденные и Subfinder, и Amass, де-дуплицируются: `source`
  расширяется (например, `crtsh,subfinder,amass`) — повторные запуски не создают
  дубликатов.
- В графе домен с ASN-атрибуцией отображает узел-прямоугольник `ASN <номер>` и
  пунктирную серую связь `asn_of`. Поддомены кодируются цветом по источникам:
  фиолетовый `#a855f7` — оба инструмента, синий `#3b82f6` — только Subfinder,
  оранжевый `#f97316` — только Amass.

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

## Subfinder (быстрый пассивный recon)

NodeArgus по умолчанию использует **Subfinder v2.15.0** (ProjectDiscovery) для
быстрого пассивного сбора поддоменов из OSINT-источников. Бинарник ставится в
Docker-образ и вызывается безопасным враппером
(`app/scanner/subfinder_wrapper.py`) — без shell, с валидацией домена через
`validate_domain` и передачей значения одним аргументом `argv`, поэтому
командная инъекция невозможна.

### Пассивные источники

Конфиг лежит в `/root/.config/subfinder/provider-config.yaml` и включает
публичные источники без API-ключей: **crtsh, hackertarget, alienvault,
commoncrawl, waybackarchive**. Для подключения приватных провайдеров (SecurityTrails,
Virustotal и др.) добавьте ключи в этот файл.

### Пайплайн обработки

1. `run_subfinder(domain)` запускает `subfinder -d <domain> -json -silent`
   (таймаут 300 секунд) и парсит JSONL построчно.
2. `run_recon_task` (или `run_subfinder_collect_task` внутри объединённой
   разведки) собирает найденные имена.
3. DNS-резолвинг выполняется батчами по 50 с ограничением одновременных
   запросов (`asyncio.Semaphore(16)`).
4. Результаты сохраняются идемпотентно (`INSERT ... ON CONFLICT DO NOTHING`),
   затем используются как цель для активного сканирования или для графа.

### Запуск через API

```bash
curl -X POST http://localhost:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"example.com","scan_type":"recon","recon_tools":["subfinder"]}'
```

Статус задачи читается стандартным `GET /scan/<task_id>/status`.

### Ручная проверка внутри контейнера

```bash
docker compose exec celery_worker subfinder -d example.com -json -silent
```

Subfinder работает быстро (обычно секунды-минуту) и служит «первым слоем»
разведки; для глубокого ASN/инфраструктурного анализа поверх него запускается
Amass.

## OWASP Amass (Deep Recon)

NodeArgus интегрирует **OWASP Amass v4.2.0** для глубокой пассивной и активной
разведки доменов: расширенный пассивный сбор поддоменов, DNS-брутфорс, ASN и
CIDR-атрибуция, обратный DNS-поиск и инфраструктурный OSINT. Результаты Amass
дополняют данные Subfinder: один и тот же поддомен, найденный обоими
инструментами, хранится один раз, а поле `source` расширяется
(`crtsh` → `crtsh,amass`).

### Режимы

| Режим | Команда | Назначение |
|---|---|---|
| `passive` | `amass enum -passive -d <domain>` | Пассивные data sources, без брутфорса |
| `active` | `amass enum -d <domain> -brute -w <wordlist>` | Добавляет DNS-брутфорс |

Active-режим требует `ALLOW_ACTIVE_RECON=true` в `.env` — он генерирует заметный
DNS-шум и затрагивает сторонние резолверы, поэтому по умолчанию выключен.

### Запуск через API

```bash
curl -X POST http://localhost:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"example.com","scan_type":"amass","amass_mode":"passive"}'
```

Статус задачи читается стандартным `GET /scan/<task_id>`.

### Почему Amass нужны словари для брутфорса

Пассивные источники находят только уже задокументированные в интернете
поддомены. DNS-брутфорс перебирает имена из словаря
(`subdomains-top1mil-5000.txt` — 5000 самых частых префиксов) и проверяет их
через DNS. Без словаря список проверяемых имён был бы пуст — Amass просто не
знал бы, какие имена перебирать. Лёгкий словарь ускоряет сканы, большой — даёт
больше редких имён ценой времени и шума.

### Обновление словаря без пересборки образа

Словарь лежит в `/usr/share/wordlists/amass/` внутри контейнера. Чтобы заменить
его без пересборки, смонтируйте файл с хоста (volume mount):

```yaml
# docker-compose.yml, сервис celery_worker:
volumes:
  - /path/to/your/subdomains-top1mil-5000.txt:/usr/share/wordlists/amass/subdomains-top1mil-5000.txt
```

Затем укажите путь переменной `AMASS_WORDLIST_PATH` (по умолчанию уже указывает
на этот файл). После правки volume достаточно `docker compose up -d celery_worker`.

Пересборка образа с новой версией Amass или словарём:

```bash
docker compose down
docker compose build --no-cache celery_worker
docker compose up -d
```

Ручная проверка внутри контейнера:

```bash
docker compose exec celery_worker amass enum -passive -d example.com -config /root/.config/amass/config.yaml -timeout 1
```

> [!NOTE]
> В Amass v4.x (в отличие от v3) у подкоманды `intel` нет флагов `-passive` и
> `-json`, а `enum` выводит найденные связи (FQDN → IPAddress → ASN/CIDR) прямо в
> stdout. Команда из ранних версий документации
> `amass intel -d example.com -passive -json` в v4.2.0 завершится ошибкой
> «flag provided but not defined: -passive». Правильный ручной эквивалент — команда
> `amass enum` выше; именно её вызывает враппер NodeArgus.

## Почему мерж результатов после DNS-резолвинга эффективнее

Мы сначала де-дуплицируем поддомены (по имени), затем один раз резолвим каждый
уникальный поддомен. Это дешевле, чем резолвить каждую выдачу инструментов по
отдельности, потому что **связь «поддомен → IP» — это many-to-many**:

- один поддомен (например, CDN `cdn.example.com`) может резолвиться в несколько
  IP (`104.20.23.154`, `172.66.147.243`, …);
- разные поддомены часто резолвятся в **один и тот же** IP (общий хост/LB).

Дедупликация до резолвинга даёт ровно один DNS-запрос на уникальное имя, а
объединение IP после резолвинга не теряет ни одной связки. Резолв каждого имени
по батчам из 50 ограничивает веер DNS-запросов (не блокирует сеть и DNS-серверы
постоянным потоком).

## Активный режим Amass в UI

Active-режим Amass (`-brute` по словарю `subdomains-top1mil-5000.txt`) генерирует
заметный DNS-шум и может выполняться **10–30 минут**. В интерфейсе это отражено:

- предупреждение в форме (Amass Active);
- `GET /scan/{task_id}/status` возвращает прогресс по каждому инструменту
  (`progress: {"subfinder":"success","amass":"running"}`), который TaskStatus
  отображает как per-tool индикаторы;
- Active mode требует `ALLOW_ACTIVE_RECON=true` в `.env`.

Команда для тестирования полного пайплайна объединённой разведки:

```bash
curl -X POST http://localhost:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"example.com","scan_type":"recon","recon_tools":["subfinder","amass"],"amass_mode":"passive"}'
TASK_ID=<id из ответа>
curl http://localhost:8000/scan/$TASK_ID/status   # следить за progress
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

DB-ориентированные тесты (`test_recon_db.py`, `test_amass_db.py`) пересоздают
все таблицы и используют выделенную БД `nodeargus_test`, чтобы не трогать
prod-данные. Создайте её один раз:

```bash
docker compose exec postgres psql -U nodeargus -c "CREATE DATABASE nodeargus_test;"
```

Если БД другая — задайте `POSTGRES_TEST_DATABASE` в `.env`.

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
