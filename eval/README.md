# Оценка качества и тестовый корпус (Evaluation & Benchmarks)

## 1. Резюме (Executive Summary)

Стенд оценки качества предназначен для непрерывной валидации точности и безопасности анализатора `vuln-analyzer` на реальных advisory и кодовой базе продуктов.

### Главные инварианты
* **`false-safe = 0`**: анализатор никогда не объявляет уязвимость безопасной (`NO_EXPLOIT_PATH_FOUND`), если есть хоть малейшая теоретическая возможность её эксплуатации.
* **Отсутствие найденного exploit path не доказывает его отсутствие**: если путь к дефекту не найден синтаксически, вердикт остаётся `UNKNOWN` или `INCONCLUSIVE`, направляя кейс на ручной триаж человеку.
* **Отрицательные вердикты строго доказаны**:
  * `NOT_AFFECTED` — только детерминистической цепочкой сборки (`go list -deps`).
  * `NO_EXPLOIT_PATH_FOUND` — только при наличии верифицированного фальсификатора (`VERIFIED Falsifier`) на обязательном условии эксплуатации.

### Ключевые метрики baseline-прогона

| Метрика | Значение | Описание |
|---|---|---|
| **Всего кейсов** | **38** | Реальные уязвимости в 12 классах зависимостей Go |
| **Cleared Rate** | **20 / 38 (53%)** | Доказанное закрытие алертов без участия человека (`NOT_AFFECTED` + `NO_EXPLOIT_PATH_FOUND`) |
| **Signal-Cleared Rate** | **9 / 27 (33%)** | Безопасное снятие алертов там, где `govulncheck` выдал шумные сигналы (`REACHABLE` / `package-level`) |
| **False-Safe Rate** | **0 / 38 (0%)** | Строгий инвариант: ни одного ложно-безопасного вердикта |
| **Требуют триажа** | **18 / 38 (47%)** | 18 / 38 (47%) доказанно уязвимых (`EXPLOITABLE`), 0 / 38 (0%) с недостаточным контекстом (`INCONCLUSIVE`) |

---

## 2. Быстрый запуск (CLI Quickstart)

### Прогон всего корпуса
Параллельный запуск всех 38 кейсов с автоматической генерацией манифестов `go.mod`/`go.sum` и переиспользованием кэша:
```bash
izyan eval --corpus eval/corpus-real.json -j 4
```

### Запуск и отладка отдельного кейса
Запуск конкретного сценария (занимает 5–9 секунд):
```bash
izyan eval --corpus eval/corpus-real.json --case real-jwt-auth
izyan eval --corpus eval/corpus-real.json --case real-micro-plain-6443x
```

### Основные флаги
* `-j <N>` — количество параллельных воркеров (по умолчанию 1).
* `--case <ID>` — фильтрация прогона по идентификатору сценария.
* `--mem-limit <size>` — лимит оперативной памяти с watchdog-контролем (по умолчанию `4GiB`).
* `--cve-analysis <off|assist|verified>` — включение автономного AI-исследователя для формирования структурированного досье:
  * `assist`: автономный исследователь с function calling (`read_patch_diff`, `inspect_source_file`, `analyze_product_scope`) формирует техническое досье и формулирует Human Remainder (точный остаток ручной работы для эксперта);
  * `verified`: строгая валидация обязательств доказательства (Proof Obligations).
* `--strict-llm` — режим fail-fast: при ошибке LLM API или бюджетов модель не переключается скрытно на детерминистический код, а завершает кейс со статусом ошибки.
* `--non-locus-basis <file>` / `--accept-locus-proposals` — утверждение рекомендаций об исключении вспомогательных функций транспорта из дефектного локуса.

---

## 3. Бизнес-эффект: сравнение с govulncheck (Decision Impact)

Ключевая ценность `vuln-analyzer` относительно стандартного `govulncheck` — кардинальное снижение операционного шума (false positives) при сохранении абсолютной безопасности.

| Кейс корпуса | Сигнал govulncheck | Вердикт vuln-analyzer | Практический статус и бизнес-эффект для команды |
|---|---|---|---|
| **`real-micro-plain-6443x`**<br>(GO-2026-6443 / gRPC authority panic) | 🔴 **`REACHABLE`** *(ложная тревога)* | 🟢 **`NO_EXPLOIT_PATH_FOUND`** *(Not Exploitable)* | **Разделение сайта дефекта и транспорта.** `govulncheck` бьёт тревогу из-за вызова `HandleStreams` в цикле сервера. Без анализатора команда вынуждена экстренно обновлять gRPC во всех сервисах. Анализатор локализует дефект в `RouteAndProcess`, доказывает отсутствие паникующего пакета в бинаре и снимает ложную тревогу с готовым обоснованием. |
| **`real-micro-pkg-6443`**<br>(GO-2026-6443 / subpackage) | 🔴 **`REACHABLE`** *(ложная тревога)* | 🟢 **`NO_EXPLOIT_PATH_FOUND`** *(Not Exploitable)* | **Недостижимость дефекта внутри скомпилированного пакета.** Пакет слинкован в бинарь, но дефектный локус `RouteAndProcess` никогда не вызывается продуктом. Анализатор доказывает недостижимость через фальсификатор `locus-function-unreached`. |
| **`real-yaml-const`**<br>**`real-yaml3-const`**<br>**`real-protojson-const`**<br>(DoS парсеров) | 🔴 **`REACHABLE`** *(ложная тревога)* | 🟢 **`NO_EXPLOIT_PATH_FOUND`** *(Not Exploitable)* | **Анализ происхождения данных (Data Provenance).** `govulncheck` видит вызов `yaml.Unmarshal`. Анализатор доказывает, что входной payload — это константа времени компиляции (`const`), изолирует внутреннюю рефлексию парсера по выходной структуре и подтверждает невозможность атаки. |
| **`real-yaml-file`**<br>(GO-2021-0061 / YAML DoS) | 🔴 **`REACHABLE`** *(ложная тревога)* | 🟢 **`NO_EXPLOIT_PATH_FOUND`** *(Not Exploitable)* | **Доверенная инфраструктура.** Аргумент парсера читается из локального файла конфигурации хоста (`os.ReadFile`), что верифицировано как доверенная среда развёртывания (`trusted infrastructure`). |
| **`real-micro-plain`**<br>(GO-2026-6441 / gRPC RBAC bypass) | ⚠️ **`module-level`** *(шумная находка)* | 🟢 **`NOT_AFFECTED`** *(Not Affected)* | **Детерминистический анализ сборки.** Модуль gRPC числится уязвимым в манифесте, но пакет `rbac` отсутствует в `go list -deps`. Анализатор детерминированно подтверждает неприменимость уязвимости. |
| **`real-micro-plain-6443`**<br>(контроль без исключения локуса) | 🔴 **`REACHABLE`** | 🔴 **`EXPLOITABLE`** | **Консервативный контроль безопасности.** Если сайт дефекта не сужен экспертом или флагом `--accept-locus-proposals`, анализатор не делает эвристических допущений и повторяет консервативный вердикт `govulncheck`. |

---

## 4. Сводная таблица baseline-прогона (38 кейсов)

Результаты последнего прогона на автономном корпусе `eval/corpus-real.json`:

| Кейс | Вердикт анализатора | Сигнал govulncheck | Статус снятия (Cleared) и обоснование |
|---|---|---|---|
| `real-yaml-http` | EXPLOITABLE | reachable | нет — внешний сетевой ввод в unmarshal |
| `real-yaml-file` | NO_EXPLOIT_PATH_FOUND | reachable | **да — чтение локального файла конфигурации хоста (trusted infrastructure) + verified negative check** |
| `real-yaml-http-fixed` | NOT_AFFECTED | silent | **да — детерминистически безопасная версия** |
| `real-md-render` | EXPLOITABLE | reachable | нет — недоверенный ввод рендерится в HTML |
| `real-getter-fetch` | EXPLOITABLE | reachable | нет — аргумент URL передается злоумышленником |
| `real-getter-const` | EXPLOITABLE | reachable | нет — protocol-switch через `X-Terraform-Get` держит `GitGetter` достижимым |
| `real-ssh-server` | EXPLOITABLE | reachable | нет — уязвимый SSH-хэндлер активен |
| `real-ssh-keyparse` | NO_EXPLOIT_PATH_FOUND | package-level | **да — govulncheck-silence + проверка недостижимости неэкспортированных субъектов в коде зависимости** |
| `real-jose-decrypt` | EXPLOITABLE | reachable | нет — парсинг токенов без ограничений |
| `real-jwt-auth` | EXPLOITABLE | package-level | нет — уязвимость в пропуске проверки (missing-call): `VerifyAudience` опущена на активном конвейере `MapClaims.Valid` (EV-MISSING-CALL) |
| `real-http2-server` | NOT_AFFECTED | silent | **да — детерминистически безопасная версия** |
| `real-dns-zone` | EXPLOITABLE | reachable | нет — сетевой парсер DNS-зон достижим |
| `real-getter-file` | EXPLOITABLE | reachable | нет — file-схема подвержена инъекциям |
| `real-getter-fixed` | NOT_AFFECTED | silent | **да — детерминистически безопасная версия** |
| `real-yaml-const` | NO_EXPLOIT_PATH_FOUND | reachable | **да — compile-time константный payload + verified negative check** |
| `real-yaml3-http` | EXPLOITABLE | reachable | нет — YAML v3 уязвим к DoS на внешнем вводе |
| `real-yaml3-const` | NO_EXPLOIT_PATH_FOUND | reachable | **да — compile-time константный payload + verified negative check** |
| `real-protojson-http` | EXPLOITABLE | reachable | нет — protojson unmarshal уязвим на внешнем вводе |
| `real-protojson-const` | NO_EXPLOIT_PATH_FOUND | reachable | **да — compile-time константный payload + verified negative check** |
| `real-protojson-fixed` | NOT_AFFECTED | silent | **да — детерминистически безопасная версия** |
| `real-dns-fixed` | NOT_AFFECTED | silent | **да — детерминистически безопасная версия** |
| `real-dns-marshal` | NO_EXPLOIT_PATH_FOUND | package-level | **да — dep-internal вызовы отсутствуют, диспетчеризация через интерфейсы исключена** |
| `real-md-fixed` | NOT_AFFECTED | silent | **да — детерминистически безопасная версия** |
| `real-ssh-fixed` | NOT_AFFECTED | silent | **да — детерминистически безопасная версия** |
| `real-jose-fixed` | NOT_AFFECTED | silent | **да — детерминистически безопасная версия** |
| `real-ssh-callback` | EXPLOITABLE | reachable | нет — callback авторизации уязвим |
| `real-micro-xds` | EXPLOITABLE | package-level | нет — внутренняя цепочка диспетчеризации фильтров доказана через статическое разрешение функциональных полей и method values в gRPC xDS |
| `real-micro-xds-fixed` | NOT_AFFECTED | silent | **да — детерминистически безопасная версия** |
| `real-micro-plain` | NOT_AFFECTED | module-level | **да — пакет rbac не входит в build graph продукта** |
| `real-micro-plain-6443` | EXPLOITABLE | reachable | нет — консервативный контроль: без сужения локуса транспортный символ в трейсе считается уязвимым |
| `real-micro-plain-6443x` | NO_EXPLOIT_PATH_FOUND | reachable | **да — locus-package-absent: транспортные функции исключены из локуса, дефектный xds-пакет вне сборки** |
| `real-micro-xds-6443` | EXPLOITABLE | reachable | нет — xDS-режим включен, уязвимый код вызывается |
| `real-micro-wrap-6443` | EXPLOITABLE | reachable | нет — xDS через фабричную обертку достигает уязвимого локуса |
| `real-micro-pkg-6443` | NO_EXPLOIT_PATH_FOUND | reachable | **да — locus-function-unreached: xds-пакет в сборке, но уязвимая функция `RouteAndProcess` недостижима** |
| `real-unix-access` | EXPLOITABLE | reachable | нет — `unix.Access` вызывается на внешнем пути |
| `real-unix-stat` | NO_EXPLOIT_PATH_FOUND | package-level | **да — zero-refs: уязвимый метод `unix.Faccessat` не используется, а внутренний caller `unix.Access` мертв** |
| `real-unix-fixed` | NOT_AFFECTED | silent | **да — детерминистически безопасная версия** |
| `real-ssh-slowpesh` | EXPLOITABLE | reachable | нет — DoS медленного рукопожатия подтвержден |

---

## 5. Структура тестовых корпусов

### 5.1. Автономный корпус (`eval/corpus-real.json`)
38 сценариев на базе микропродуктов из каталога `eval/products/`. Манифесты `go.mod` и `go.sum` генерируются автоматически в `eval/.gen/<case-id>` на основе полей `module` и `deps`. Стенд полностью автономен и не требует доступа к внешним закрытым репозиториям.

Покрывает 12 классов уязвимостей:
1. **YAML DoS** (v2 GO-2021-0061, v3 GO-2022-0603) — парсинг циклических и глубоких структур;
2. **Markdown XSS / Render** (GO-2023-2074) — экранирование при генерации HTML;
3. **Command / Argument Injection** (GO-2024-2800 в `go-getter`) — инъекция аргументов протокола `git::`;
4. **SSH / Crypto** (GO-2022-0968 паника, GO-2024-3321 обход авторизации, GO-2025-3487 медленное рукопожатие);
5. **JOSE Algorithm Confusion** (GO-2023-2409) — дешифрование токенов с небезопасными заголовками;
6. **JWT Missing-Call Validation** (GO-2020-0017 в `jwt-go`) — пропуск проверки аудитории;
7. **HTTP/2 Rapid Reset** (GO-2023-2102) — DoS мультиплексирования потоков;
8. **DNS Zone Parse** (GO-2020-0028 в `miekg/dns`) — паника парсера некорректных записей зон;
9. **Protobuf Protojson Loop** (GO-2024-2611) — бесконечный цикл парсера некорректных структур;
10. **gRPC xDS RBAC Bypass** (GO-2026-6441) — дефекты применения политик доступа;
11. **gRPC xDS Authority Panic** (GO-2026-6443) — дефектный локус паники заголовка `:authority`;
12. **Unix Faccessat Privilege Check** (GO-2022-0493) — некорректный опрос прав доступа на Linux.

### 5.2. Интеграционный live-корпус (`eval/live-corpus.json`)
11 advisory против реального монорепозитория (`${VA_PRODUCT_REPO}`) и библиотеки `github.com/rabbitmq/amqp091-go` v1.10.0. Используется для валидации глубоких потоков данных на тяжелом промышленном коде с фоновыми горутинами, рефлексией и сложным маппингом конфигурации.

Запуск:
```bash
PATH=$HOME/go/bin:$PATH VA_PRODUCT_REPO=<product-repo> izyan eval --corpus eval/live-corpus.json
```

Подробная ручная разметка истинности (ground truth), доказательная база и история анализа кейсов вынесены в отдельный документ: [`eval/ground-truth.md`](ground-truth.md).

---

## 6. Механика доказательств и масштабируемость

### Контроль неопределенности и безопасные отрицания
* **Инвариант отрицательного вывода**: вердикт `NO_EXPLOIT_PATH_FOUND` выносится только тогда, когда опровергнуто хотя бы одно обязательное условие эксплуатации (`mandatory condition`), а отрицание подтверждено фазой негативной верификации (`Negative Verification: VERIFIED`).
* **Субъектно-ориентированная непрозрачность и инстанцирование рефлексии (B19)**:
  В кейсе `ghsa-465g-fh3v-9jw4` (URI confusion) внутренние вызовы зависимостей считаются непрозрачными только если они потенциально достигают дефектного субъекта. Маркер `reflect_method` в негативной верификации фильтруется по наличию инстанцирования типа ресивера (`amqp091.URI`) в продукте или коде зависимостей: отсутствие созданных экземпляров типа не позволяет динамическому вызову опровергнуть безопасность отрицательного условия, подтверждая вердикт `NO_EXPLOIT_PATH_FOUND`.

  #### Эволюция отчёта анализатора (Case Study: GHSA-465g):
  * **До закрытия B19 (`INCONCLUSIVE`):**
    - `C-ROUNDTRIP`: `UNKNOWN` (ограничение: *«pair member(s) ... not statically reached; module dispatch is opaque (func values/dynamic dispatch)»* из-за сетевого диалера и вызовов `error.Error()` в кодовой базе зависимости).
    - `Negative Verification`: даже при потенциальном FALSE общий маркер `reflect_method` в коде продукта порождал ограничение *«reflect method dispatch usage in product widens the call graph»*, приводя к демоции вердикта.
    - **Итог отчёта:** *«Требуется ручной анализ (Inconclusive)»*.
  * **После закрытия B19 (`NO_EXPLOIT_PATH_FOUND`):**
    - `ModuleInternalReach`: доказано, что ни один непрозрачный сайт в `amqp091-go` (сетевые диалеры с сигнатурой `func(string, string) (net.Conn, error)`, дедлайны `SetDeadline`) не совместим по сигнатуре/интерфейсу с методом `URI.String() func() string`. Вызовы predeclared-функций (`error.Error()`) корректно классифицированы как статические. Непрозрачность снята (`opaque = false`).
    - `Negative Verification`: проверено, что именованный тип `amqp091.URI` продуктом не инстанцируется (нет композитных литералов, `new()`, `make()`, явных переменных или возвратов вызываемых API). Динамический вызов метода через `reflect.Value.MethodByName` физически не имеет объекта в памяти. Маркер `reflect_method` отфильтрован без внесения ограничений (`Status: VERIFIED`).
    - `C-ROUNDTRIP`: подтверждён результат **`FALSE`** с фальсификатором `missing-pair-member` на обязательном условии.
    - **Итог отчёта:** чёткий аудируемый вердикт **`NO_EXPLOIT_PATH_FOUND`** (0 fail, 0 false-safe). Раздел `## Резюме` формирует готовый комментарий для закрытия тикета безопасности без необходимости отвлекать инженеров на ручной триаж.
* **Защита от ложной безопасности при пропущенных проверках (missing-call)**:
  В кейсе `real-jwt-auth` метод `VerifyAudience` физически не вызывается в программе. Наивный сканер посчитал бы отсутствие вызова доказательством безопасности. В анализаторе действует защитный предохранитель (`DepInvocationState`): если целевая проверка не вызывается, но родственные методы валидации того же типа (`MapClaims.Valid`) активно обрабатывают внешний ввод, отсутствие вызова блокирует отрицательный вердикт и сохраняет `INCONCLUSIVE`.
* **Защита константных данных от рефлексии парсеров**:
  В кейсах `real-yaml-const`, `real-yaml3-const`, `real-protojson-const` входные байты строго доказаны как компиляторные константы. Рефлексивные операции парсера по заполнению выходной структуры изолируются и не аннулируют неизменяемость входных данных.
* **Доверенная инфраструктура**:
  В кейсе `real-yaml-file` доказано, что входные данные поступают исключительно из локального файла конфигурации хоста через `os.ReadFile`. При отсутствии внешнего контроля над путем к файлу это признается доверенной средой (`FalsifierTrustedInfrastructure`).

### Масштабируемость и защита от OOM (Memory Management)
Для исключения зависаний и переполнения памяти при сканировании крупных зависимостей (например, `go-getter`, `grpc`, `crypto`):
1. **LRU-эвикция AST**: синтаксические деревья пакетов зависимостей загружаются точечно и выгружаются из памяти при превышении квот (≤40 пакетов / ≤500 файлов), очищая связанные деревья типов.
2. **Ограничение комбинаторного взрыва графа вызовов**: кэш классификации вызовов (`classifyCache`) сворачивает экспоненциальный fan-out трассировки (время анализа `yaml-file` снижено с 413с до 8с).
3. **Лимиты fan-out и бюджетов**: попозиционный бюджет выражений и бюджет сессий трассировки (`evalBudget`) защищают анализ от зацикливания.
4. **Watchdog памяти**: фоновый процесс с порогом `--mem-limit` (по умолчанию 4GiB) выполняет принудительный возврат неиспользуемых страниц памяти операционной системе (`debug.FreeOSMemory()`).
