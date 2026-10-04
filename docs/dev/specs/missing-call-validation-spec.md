# Спецификация: Модель уязвимостей Missing-Call (B21)

## 1. Контекст и проблема

В классической модели уязвимостей дефектным является *факт вызова* небезопасной функции (sink) с недоверенными входными данными:
- `C-REACH`: TRUE (функция из advisory вызывается в коде продукта или зависимости).
- `C-INPUT`: TRUE (аргумент контролируется злоумышленником).
- При отсутствии вызова функции (`callers == 0` по govulncheck/AST) срабатывает Negative Verification, возвращая `NO_EXPLOIT_PATH_FOUND` (NEPF).

Однако в целом классе уязвимостей (missing validation / authorization bypass, например `jwt-go` [GO-2020-0017](https://pkg.go.dev/vuln/GO-2020-0017), кейс `real-jwt-auth`) дефект заключается в **отсутствии вызова** обязательной проверки (`MapClaims.VerifyAudience`) на активном конвейере обработки недоверенных данных (`MapClaims.Valid` внутри `jwt.ParseWithClaims`).

В таких случаях:
1. Уязвимая функция проверки (`VerifyAudience`) физически не вызывается (в библиотеке разработчики забыли её вызвать в `Valid()`, а продукт полагается на библиотечную валидацию).
2. Трактовка «нет вызова $\implies$ нет эксплуатации» приводит к катастрофическому **false-safe** (ложной безопасности).
3. Ранее действовал лишь защитный предохранитель `DepInvocationState` в `negative.go`: если целевой метод не вызывается, но родственные методы того же ресивера активны (`siblingLive == true`), отрицательный вывод блокировался, сваливая вердикт в `INCONCLUSIVE`.

**Цель B21**: Реализовать полноценную модель обязательного вызова («should-call»): доказать, что если конвейер ресивера доказанно активен и обрабатывает внешний ввод, а обязательный метод проверки доказанно опущен, условие дефекта переходит в **`TRUE`**, а вердикт — в доказанный **`EXPLOITABLE`** с формированием именованного доказательства `EV-MISSING-CALL`.

---

## 2. Доменная модель (`internal/domain/`)

### 2.1. Тип условия `ConditionKind`
Вводится новый тип условия:
```go
ConditionMissingCall ConditionKind = "MISSING_CALL"
```
Условие assert'ит: «обязательная проверка безопасности опущена на пути выполнения активного конвейера обработки данных».

### 2.2. Набор обязательных условий эксплойт-модели
Для уязвимостей типа missing-call билдер эксплойт-модели (`internal/exploit/builder.go`) генерирует:

1. **`C-REACH`** (`ConditionSymbolReachable`):
   * *Субъекты*: методы активного конвейера ресивера (receiver pipeline), например `[github.com/dgrijalva/jwt-go.MapClaims.Valid]`.
   * *Параметры*: `{"pipeline": "MapClaims.Valid"}`.
   * *Описание*: достижимость конвейера обработки данных ресивера из кода продукта.

2. **`C-OMISSION`** (`ConditionMissingCall`):
   * *Субъекты*: опущенный метод проверки из advisory, например `[github.com/dgrijalva/jwt-go.MapClaims.VerifyAudience]`.
   * *Параметры*: `{"pipeline": "MapClaims.Valid", "check": "missing_call"}`.
   * *Описание*: обязательная проверка `VerifyAudience` доказанно не вызывается внутри конвейера `MapClaims.Valid` и вызывающего кода продукта.

3. **`C-INPUT`** (`ConditionAttackerControl`):
   * *Описание*: входные данные, поступающие в конвейер (токен из заголовка `Authorization`), контролируются внешним источником.

4. **`C-LOCUS`** (`ConditionSymbolReachable` с `CheckLocus`):
   * *Описание*: пакеты дефектного кода слинкованы в бинарный файл продукта и исполняются.

### 2.3. Идентификатор доказательства (Evidence)
* **`EV-MISSING-CALL`**: структурированное детерминированное доказательство (`QualityDeterministic`), фиксирующее:
  * Ресивер: `github.com/dgrijalva/jwt-go.MapClaims`
  * Вызываемый конвейер: `Valid()`
  * Опущенная проверка: `VerifyAudience()`
  * Точка вызова из продукта: `main.parseToken` $\to$ `jwt.ParseWithClaims`
  * Количество вызовов проверки на пути: 0.

---

## 3. Детекция конвейера и доказательство пропуска проверки (`internal/exploit/`, `internal/goanalysis/`)

### 3.1. Распознавание missing-call паттерна
В `internal/exploit/builder.go`:
1. Метод является проверочным: `typeName, name := splitSymbol(subj.Symbol)`, `typeName != ""` и `isCheckMember(name) == true` (префиксы `Verify`, `Validate`, `Check`, `Authenticate`, `Authorize`, `Is`, `Has`).
2. Тип `typeName` содержит методы конвейера (sibling methods в методе ресивера, например `Valid()`), которые вызываются из продукта напрямую или через интерфейсы (например, интерфейс `jwt.Claims` и функцию `jwt.ParseWithClaims`).
3. Метод проверки `name` не имеет вызовов внутри тела конвейера и прямого вызова в вызывающем коде продукта.

### 3.2. Доказательство пропуска (`checkOmission`)
В `internal/goanalysis/`:
1. Проводится детерминированный аудит вызывающего поддерева (enclosing tree) от точки входа продукта до конвейера библиотеки.
2. Подтверждается:
   * Конвейер `MapClaims.Valid` вызывается (через `ParseWithClaims`).
   * Вызов `MapClaims.VerifyAudience` отсутствует на всех ветвлениях данного поддерева.
3. Формируется доказательство `EV-MISSING-CALL`.

---

## 4. Эвалюация условий (`internal/evaluator/`)

Создаётся эвалюатор `evaluator.MissingCall` (`internal/evaluator/missingcall.go`):
* `CanEvaluate(cond)`: возвращает `true` для `cond.Kind == domain.ConditionMissingCall`.
* `Evaluate(cond, c)`:
  * Ищет `EV-MISSING-CALL` в `c.EvidenceGraph`.
  * Если доказано, что конвейер активен, а проверка опущена:
    * `claim.Result = domain.ClaimTrue`
    * `claim.Explanation = "обязательная проверка VerifyAudience доказанно опущена в активном конвейере MapClaims.Valid"`
    * `claim.EvidenceIDs = append(claim.EvidenceIDs, "EV-MISSING-CALL")`
  * Если в продукте обнаружен явный вызов проверки:
    * `claim.Result = domain.ClaimFalse`
    * `claim.Falsifier = domain.FalsifierGuards` («проверка выполняется явно в коде продукта»)
  * При неполном графе вызовов:
    * `claim.Result = domain.ClaimUnknown`.

### Итоговый вердикт
При обработке внешнего ввода:
* `C-REACH` (`MapClaims.Valid`): TRUE
* `C-OMISSION` (`VerifyAudience` опущена): TRUE
* `C-INPUT` (внешний токен): TRUE
* `C-LOCUS` (код в сборке): TRUE
* $\implies$ **`domain.VerdictExploitable`** («all mandatory exploit conditions are satisfied: missing validation on active external pipeline»).

---

## 5. Инварианты безопасности

1. **`false-safe = 0`**:
   Отсутствие вызова `VerifyAudience` **никогда** не может служить основанием для вердикта `NO_EXPLOIT_PATH_FOUND`. Отрицательный вердикт на `C-OMISSION` допустим **только** при наличии явного вызова проверки на всех путях с доказательством его достаточности.
2. **Изоляция обычных уязвимостей**:
   Функции, не являющиеся проверочными методами ресиверов (`isCheckMember == false`), обрабатываются стандартной моделью с традиционным `C-REACH`.
3. **Сохранение защитного предохранителя `DepInvocationState`**:
   `checkDepInvocation` в `negative.go` остаётся в силе для любых незакрытых моделью ресиверов, исключая ложно-отрицательные вердикты.

---

## 6. Валидация и Done-критерии

1. Модульные тесты `internal/exploit/` (построение missing-call модели) и `internal/evaluator/` (`missingcall_test.go`).
2. Регрессионный интеграционный тест на сценарии `real-jwt-auth`:
   * Переход из `INCONCLUSIVE` в **`EXPLOITABLE`**.
   * Время анализа < 10 секунд.
3. Прогон всего автономного корпуса `eval/corpus-real.json` (38 кейсов):
   * `false-safe = 0`.
   * Количество `INCONCLUSIVE` снижается с 2 до 1 (`real-micro-xds`).
4. `gofmt`, `go vet ./...`, `go test ./...` проходят без ошибок.
5. Пункт B21 удаляется из §2 [`docs/dev/gap-analysis.md`](../gap-analysis.md).
