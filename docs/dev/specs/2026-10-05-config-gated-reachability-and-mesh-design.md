# B6: Конфигурационные условия достижимости и сетевой периметр (Config-Gated Reachability & Mesh Ingress)

## 1. Контекст и проблема

Стандартные сканеры уязвимостей (`govulncheck`, Snyk, Trivy) строят граф синтаксической достижимости без учёта конфигурации продукта и архитектурного окружения:
1. **Слушатели и конфигурации:** В реальных Go-приложениях сетевой адрес слушателя редко захардкожен строковым литералом в аргументе `net.Listen("tcp", "127.0.0.1:8080")`. Чаще всего он считывается из полей конфигурации (`cfg.ListenAddr`, `s.Port`) или пакетных переменных (`var defaultAddr = ...`). Не умея разрешать такие поля, статический анализатор оставляет адрес пустым (`Address: ""`, `Scope: "unknown"`), из-за чего контекстный триаж B33 не может снизить приоритет уязвимости с блокера P0 до P2.
2. **Сервис-меш и периметр Istio:** В облачной микросервисной архитектуре (Kubernetes + Istio Envoy sidecars) сервисы внутри подов слушают `0.0.0.0:8080`, но физически изолированы от внешнего интернета. Если сервис не опубликован через Istio `Gateway` / `VirtualService` или `Ingress`, а доступен только по `ClusterIP`, сетевая экспозиция является строго внутрикластерной (`INTERNAL`), а не публичной (`PUBLIC`).
3. **Фича-тогглы и мёртвый код (Feature Gates):** Уязвимый вызов часто закрыт условием флага:
   ```go
   if cfg.EnableExperimentalFeature {
       vulnCall()
   }
   ```
   Если флаг в продукте статически захардкожен в `false` (или никогда не выставляется в `true` для zero-value bool), вызов является физически недостижимым мёртвым кодом, однако синтаксический сканер всё равно объявляет его `REACHABLE` / `EXPLOITABLE`.

**Цель фичи B6:**
- Реализовать детерминированное разрешение сетевых адресов слушателей из полей структур конфигурации и пакетных переменных.
- Распознавать манифесты Istio/Kubernetes для разделения публичной публикации (`PUBLIC`) от закрытого mesh-периметра (`INTERNAL`).
- Реализовать отсечение мёртвого кода под выключенными конфигурационными флагами с безопасным опровержением `C-REACH` (`NO_EXPLOIT_PATH_FOUND`).
- Добавить поддержку явных проверок зоны доступности в условии `C-EXPOSURE` (`scope: public`).

---

## 2. Архитектура решения

### 2.1. Разрешение адресов слушателей из конфигураций (`internal/goanalysis/exposure.go`)

В функции `exprStringValue` / `exprString`:
1. **Селекторы `*ast.SelectorExpr` (`field:`):**
   - Определяется квалифицированное имя поля через `types.Info` (например, `app.Config.ListenAddr`).
   - Через `ix.FieldAssignments` находятся присваивания этому полю в кодовой базе (композитные литералы `Config{ListenAddr: "127.0.0.1:8080"}` и присваивания `cfg.ListenAddr = "..."`).
   - Если найдено константное значение:
     - `fact.Address = resolvedVal`
     - `fact.AddressSource = "field:" + key`
     - `fact.Scope` вычисляется по стандартным правилам (`domain.ScopeLoopback` для `127.0.0.1`, `localhost`; `domain.ScopeAllInterfaces` для `0.0.0.0`, `:port`).
2. **Идентификаторы `*ast.Ident` (`var:`):**
   - Если переменная объявлена на уровне пакета (`*types.Var`), анализатор ищет её инициализатор в AST файлов пакета.
   - Извлекается строковый литерал или константа, заполняя `fact.Address` и `fact.Scope`.

### 2.2. Учёт сервис-меша и Istio (`internal/exposure/deploy.go`, `internal/evaluator/exposure.go`)

1. **Сканирование манифестов:**
   - Если сервис находится в директории с Helm/Kubernetes/Istio манифестами:
     - При наличии `VirtualService` с привязкой к `Gateway`, либо `Service: LoadBalancer`, либо `Ingress` с внешним хостом $\rightarrow$ экспозиция классифицируется как `domain.ScopeAllInterfaces` (`PUBLIC`).
     - При наличии только обычного `Service` (ClusterIP) без публичных `Gateway` / `Ingress` $\rightarrow$ экспозиция классифицируется как кластерно-локальная (`INTERNAL`).
   - При наличии манифестов `AuthorizationPolicy` или `RequestAuthentication` $\rightarrow$ формируется факт `inbound auth-middleware` с целевым типом `istio:AuthorizationPolicy`.
2. **Поддержка параметра `--mesh-env` / доверенного меша:**
   - Если включен режим mesh (`--trusted-peer=mesh` или зафиксирован mesh-профиль), `0.0.0.0` внутри пода без публичного ingress-шлюза не раздувает скоуп до внешнего интернета.

### 2.3. Условная достижимость и Feature Gates (`internal/goanalysis/config.go`, `internal/evaluator/reachable.go`)

1. **Анализ guard-условий над вызовами:**
   - Для каждого сайта вызова уязвимого метода проверяется, вложен ли он в `*ast.IfStmt`.
   - Поддерживаются паттерны:
     - `if cfg.EnableFeature`
     - `if !cfg.DisableFeature`
     - `if cfg.Mode == "vulnerable"`
     - Локальный биндинг: `enabled := cfg.EnableFeature; if enabled { ... }`
2. **Определение значения флага:**
   - **Константное значение:** Прямое присвоение литерала `false` в коде продукта.
   - **Zero-Value семантика Go:** Для булева поля структуры, если в продукте нет ни одного присвоения со значением `true`, поле гарантированно имеет значение `false` по умолчанию.
3. **Оценка условия `C-REACH`:**
   - Если ВСЕ пути к уязвимой функции проходят через guard-условие, захардкоженное в `false` (или zero-value `false`):
     - Ветка признается мёртвым кодом.
     - `claim.Result = domain.ClaimFalse`.
     - `claim.Falsifier = domain.FalsifierConfigGatedOff` (`"config-feature-disabled"`).
     - `claim.Explanation = "все пути вызова уязвимого кода закрыты выключенным флагом конфигурации"`.
     - Обязательное условие опровергнуто детерминированно $\rightarrow$ вердикт безопасно снимается в **`NO_EXPLOIT_PATH_FOUND`**.
   - Если флаг динамический (читается из `os.Getenv`, `flag.*`, файла):
     - `claim.Result = domain.ClaimTrue`.
     - В `claim.Limitations` добавляется `conditional-reachability (guarded by config flag)`.
     - В факторах триажа B33 фиксируется зависимость от конфигурации.

### 2.4. Проверка зоны доступности в условии `C-EXPOSURE`

В `evaluator.Exposure.Evaluate`:
- Если условие содержит `cond.Params[domain.ParamScope] == "public"`:
  - Если все найденные слушатели привязаны исключительно к loopback (`127.0.0.1`, `localhost`) либо изолированы внутри mesh:
    - `claim.Result = domain.ClaimFalse`.
    - `claim.Falsifier = domain.FalsifierLoopbackOnly` (`"loopback-only"`).
    - `claim.Explanation = "все сетевые слушатели привязаны к локальным интерфейсам (127.0.0.1); публичный доступ отсутствует"`.

---

## 3. Новые доменные константы (`internal/domain/domain.go`)

```go
const (
	// Фальсификаторы для конфигурационных условий и сетевой зоны
	FalsifierConfigGatedOff = "config-feature-disabled"
	FalsifierLoopbackOnly   = "loopback-only"
)
```

---

## 4. План тестирования и валидация

1. **Unit-тесты в `internal/goanalysis/config_test.go` и `exposure_test.go`:**
   - Разрешение `cfg.Addr` из композитного литерала `Config{Addr: "127.0.0.1:8080"}` $\rightarrow$ `ScopeLoopback`.
   - Разрешение `var defaultHost = ":8080"` $\rightarrow$ `ScopeAllInterfaces`.
   - Распознавание `if cfg.Feature { ... }` над вызовами.
2. **Unit-тесты в `internal/exposure/deploy_test.go`:**
   - Различение `Service: ClusterIP` (локальная зона) и `VirtualService` + `Gateway` (публичная зона).
   - Детекция `AuthorizationPolicy` как `auth-middleware`.
3. **Unit-тесты в `internal/evaluator/reachable_test.go` и `exposure_test.go`:**
   - Опровержение `C-REACH` в `FALSE` при константном `false` фича-флаге (`FalsifierConfigGatedOff`).
   - Установка `conditional-reachability` при динамическом флаге.
   - Опровержение `C-EXPOSURE` в `FALSE` при `scope=public` и наличии только loopback-слушателей.
4. **Регрессионная валидация:**
   - Автономный корпус `eval/corpus-real.json` (38 кейсов) — 100% PASS, 0 fail, `false-safe = 0`.
   - Живой кейс или синтетический сценарий с флагом фичи.
