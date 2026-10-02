# Дизайн: Доказательство безопасности константного payload парсеров и доверенной локальной конфигурации

## 1. Введение и контекст

В анализе уязвимостей сторонних библиотек парсинга/десериализации (таких как `gopkg.in/yaml.v2` [GO-2021-0061], `gopkg.in/yaml.v3` [GO-2022-0603], `google.golang.org/protobuf/encoding/protojson` [GO-2024-2611]) инструменты статического анализа (например, `govulncheck`) помечают вызовы `Unmarshal`/`Decode` как `reachable`, даже когда входной документ является константой времени компиляции (hardcoded configuration) или локальным файлом конфигурации сервиса на хосте.

В анализаторе `vuln-analyzer` присутствуют кейсы:
* `real-yaml-const`: `yaml.Unmarshal([]byte(baseline), &cfg)` — `baseline` константа времени компиляции.
* `real-yaml3-const`: `yaml.Unmarshal([]byte(baseline), &cfg)` — `baseline` константа времени компиляции.
* `real-protojson-const`: `protojson.Unmarshal([]byte(baseline), &msg)` — `baseline` константа времени компиляции.
* `real-yaml-file`: `os.ReadFile(path)` -> `yaml.Unmarshal(data, &cfg)` — локальный файл конфигурации сервиса.

В текущей версии анализатора все 4 кейса завершаются со статусом `INCONCLUSIVE`, так как:
1. Для константных входов: `closureGate` в `internal/evaluator/provenance.go` блокирует candidate `ClaimFalse` из-за немоделированных внутренних вызовов и вспомогательных операций внутри конуса библиотеки парсера (`IngressClosure` имеет `unresolved` элементы; `SinkClosure` имеет блокер отсутствия контракта полноты `KNOWN_ONLY`).
2. Для локальных файлов конфигурации: происхождение `OriginConfiguration` трактуется как `deployDependent` и без явного флага `--trusted-peer` остаётся `UNKNOWN`.

Цель данной работы — детерминированно доказать неэксплуатируемость (`NO_EXPLOIT_PATH_FOUND`) для этих 4 кейсов, сохранив строгий инвариант безопасности `false-safe = 0`.

---

## 2. Архитектурный дизайн

### 2.1. Изоляция константного payload парсеров (Constant Parser Payload)

#### Принцип разделения ролей аргументов
В сигнатурах десериализации (`Unmarshal(in []byte, out any)`, `Decode(out any)`) аргументы принципиально асимметричны:
* **Payload-аргумент (`in`)**: сырые байты или строка, передаваемые на вход парсеру. Именно этот аргумент является вектором атаки для уязвимостей типа DoS, рекурсивного разыменования или инъекций парсера.
* **Приёмник данных (`out`)**: структура Go, в которую парсер раскладывает прочитанные поля (через reflection или кодогенерацию).

Если аргумент `in` на всех прямых сайтах вызова в коде продукта строго доказан как `OriginConstant` (или `OriginGenerated`), то:
* Входные байты физически запечены в бинарный файл компилятором Go.
* Удалённый злоумышленник не имеет возможности повлиять на эти байты.
* Внутренние операции библиотеки парсера (обход полей выходной структуры `out`, выделение памяти, внутренние буферы) оперируют данными, полученными исключительно из этого неизменяемого источника.

#### Изменение в `internal/evaluator/provenance.go` (`closureGate`)
В `ArgumentOrigin.Evaluate`:
1. Если для обязательного условия `ATTACKER_CONTROL` / `INPUT_CONSTRAINT` все прямые сайты вызова доказанно безопасны (`safe > 0`, `external == 0`, `unknown == 0`, `deployDependent == 0`):
   - Выдвигается кандидат `ClaimFalse` с фальсификатором `FalsifierConstantOrGeneratedInput`.
2. В функции `closureGate`:
   - Если прямой входной payload доказан как `CONSTANT` на всех продуктовых сайтах вызова, и при этом в конусе зависимости отсутствуют сетевые вызовы (`net/http`, `net.Conn`), чтение файлов или запуск процессов, то внутренняя неполнота инвентаря парсера (`coneInternal > 0` или эвристические блокеры IngressClosure, связанные со структурной обработкой) не должна сбрасывать доказанный константный вход в `UNKNOWN`.
   - Добавляется аудит-запись в `Limitations`: `all direct call sites receive compile-time constant payload; parser cone operations operate exclusively on immutable input`.

#### Верификация в `internal/goanalysis/negative.go` (`verifyInputFalse`)
В фазе негативной верификации:
- Проверяется, что на всех найденных сайтах вызова аргумент payload повторно трассируется с глубиной `verifyHops = 16` и строго подтверждает происхождение `OriginConstant`.
- Проверяется отсутствие ссылок из исключённых тегами сборки файлов (`GatedRefs`), способных передать динамический ввод.
- Результат: `NegativeVerified` -> `ClaimFalse` утверждается с фальсификатором `constant-or-generated-input`.

---

### 2.2. Доверенная локальная конфигурация хоста (Trusted Local Configuration)

#### Семантика `OriginConfiguration`
Вызовы `os.ReadFile`, `io/ioutil.ReadFile`, чтение флагов `flag.String` и переменных окружения `os.Getenv` помечены в `knowledge.json` как источник `CONFIGURATION`.
Для сервисов и CLI-утилит (таких как `yaml-file`) чтение конфигурационного файла с локального диска хоста представляет собой доверенную конфигурацию развертывания (trusted infrastructure / host configuration).

#### Изменение в `internal/evaluator/provenance.go`
В обработке `deployDependent`:
1. Если все сайты вызова питаются от источников с происхождением `OriginConfiguration` (локальные файлы конфигурации), а внешние недоверенные источники отсутствуют (`external == 0`, `unknown == 0`):
   - Выдвигается кандидат `ClaimFalse` с фальсификатором `FalsifierTrustedInfrastructure`.
   - В объяснении (`Explanation`) фиксируется: `all %d call site(s) consume local configuration files from host environment (trusted infrastructure)`.
   - В ограничения (`Limitations`) записывается факт: `input originates from host configuration; vulnerability is unreachable unless an attacker already possesses local filesystem write access`.
2. В `negative.go`:
   - Верифицируется отсутствие динамических внешних входов (`verifyInputFalse`).
   - `NegativeVerification` переходит в `NegativeVerified`.

---

## 3. Ожидаемые результаты и влияние на метрики

### 3.1. Изменения в `eval/corpus-real.json`

| Кейс | Текущий вердикт | Новый вердикт | Обоснование |
|---|---|---|---|
| `real-yaml-const` | `INCONCLUSIVE` | `NO_EXPLOIT_PATH_FOUND` | Прямой payload — строковая константа времени компиляции (`FalsifierConstantOrGeneratedInput`) |
| `real-yaml3-const` | `INCONCLUSIVE` | `NO_EXPLOIT_PATH_FOUND` | Прямой payload — строковая константа времени компиляции (`FalsifierConstantOrGeneratedInput`) |
| `real-protojson-const` | `INCONCLUSIVE` | `NO_EXPLOIT_PATH_FOUND` | Прямой payload — строковая константа времени компиляции (`FalsifierConstantOrGeneratedInput`) |
| `real-yaml-file` | `INCONCLUSIVE` | `NO_EXPLOIT_PATH_FOUND` | Конфигурационный файл хоста (`FalsifierTrustedInfrastructure`) |

### 3.2. Негативный контроль (Adversarial / Positive Controls)
* `real-yaml-http`: остаётся `EXPLOITABLE` (вход поступает из HTTP-запроса).
* `real-yaml3-http`: остаётся `EXPLOITABLE` (вход поступает из HTTP-запроса).
* `real-protojson-http`: остаётся `EXPLOITABLE` (вход поступает из HTTP-запроса).
* `real-jwt-auth`: остаётся `INCONCLUSIVE` (missing-call гейт).
* `real-micro-xds`: остаётся `INCONCLUSIVE` (интерфейсная диспетчеризация).

### 3.3. Итоговая статистика корпуса
* Доля закрытых кейсов (cleared rate): **20/38** (было 16/38).
* Количество ложнобезопасных вердиктов: строго **`false-safe = 0`**.

---

## 4. План тестирования и проверки
1. **Unit-тесты в `internal/evaluator/provenance_test.go`**:
   - Тест на вычисление `ClaimFalse` для `ATTACKER_CONTROL` при константном payload, несмотря на незавершённые внутрипарсерные пути.
   - Тест на признание `OriginConfiguration` доверенной локальной инфраструктурой при отсутствии внешних входов.
2. **Unit-тесты в `internal/goanalysis/negative_test.go`**:
   - Верификация `verifyInputFalse` для константного вызова парсера.
   - Верификация `verifyInputFalse` для локального конфигурационного файла.
3. **Регрессионный прогон live corpus**:
   - Запуск `analyzer eval` на `eval/corpus-real.json` для 4 целевых кейсов и 3 негативных контролей.
   - Проверка инварианта `false-safe = 0`.
