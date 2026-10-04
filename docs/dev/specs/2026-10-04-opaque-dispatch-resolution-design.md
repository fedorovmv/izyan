# Спецификация: Разрешение непрямой диспетчеризации в зависимостях (B24)

## 1. Контекст и проблема

В бэклоге [`docs/dev/gap-analysis.md`](../gap-analysis.md) пункт **B24** описывает непрямую внутреннюю диспетчеризацию вызовов в сторонних библиотеках:
* В кейсе `real-micro-xds` (уязвимость [GO-2026-6441](https://pkg.go.dev/vuln/GO-2026-6441) в `google.golang.org/grpc v1.83.0`, продукт `eval/products/micro-xds`):
  - Продукт инициализирует xDS gRPC сервер (`xds.NewGRPCServer`) и запускает обслуживание (`srv.Serve(ln)`).
  - Уязвимый синк находится в `google.golang.org/grpc/internal/xds/httpfilter/rbac`: методы `builder.ParseFilterConfig`, `builder.ParseFilterConfigOverride` и функция `parseConfig`.
  - В реальности синк достигается по цепочке длины 25 вызовов: `Serve` $\to$ `NewListenerWrapper` $\to$ `WatchListener` $\to$ `WatchResource` $\to$ `authority.watchResource` $\to$ `xdsChannelToUse` $\to$ `getChannelForADS` $\to$ `newXDSChannel` $\to$ `newADSStreamImpl` $\to$ `runner` $\to$ `recv` $\to$ `onResponse` $\to$ `decodeResponse` $\to$ `Decoder.Decode` $\to$ `listenerResourceDecoder.Decode` $\to$ `unmarshalListenerResource` $\to$ ... $\to$ `validateHTTPFilterConfig` $\to$ `httpfilter.Builder.ParseFilterConfig` $\to$ `rbac.builder.ParseFilterConfig` $\to$ `rbac.parseConfig`.
* Однако статический анализатор (`internal/goanalysis/source.go`, метод `moduleEdges`) обрывал эту цепочку в двух местах:
  1. **Локальные method values / функциональные переменные:**
     В `validateHTTPFilterConfig`:
     ```go
     parseFunc := filterBuilder.ParseFilterConfig
     if !lds {
         parseFunc = filterBuilder.ParseFilterConfigOverride
     }
     filterConfig, err := parseFunc(config)
     ```
     Вызов `parseFunc(...)` имеет в AST `call.Fun` типа `*ast.Ident`. Функция `calleeObject(info, call.Fun)` возвращает `*types.Var`, а не `*types.Func`. Анализатор игнорировал вызов, не связывал его с интерфейсным методом `httpfilter.Builder.ParseFilterConfig` и помечал вызывающую функцию как `opaqueCaller`.
  2. **Поля структур с функциональной сигнатурой (callback dispatch):**
     В `authority.xdsChannelToUse`:
     ```go
     xc, cleanup, err := a.getChannelForADS(sc, a)
     ```
     Поле `getChannelForADS xdsChannelForADS` инициализируется при создании структуры `authority`:
     ```go
     getChannelForADS: c.getChannelForADS
     ```
     Поскольку `a.getChannelForADS` — это селектор по полю структуры, `calleeObject` возвращает `*types.Var` (поле типа `*types.Signature`), вызов не связывался с методом `XDSClient.getChannelForADS`, и цепочка обрывалась.
* В результате `real-micro-xds` оставался единственным `INCONCLUSIVE` кейсом в корпусе `eval/corpus-real.json` (37/38 разрешено).

**Цель B24**: Реализовать общее детерминированное разрешение вызовов функциональных переменных, method values и функциональных полей структур в intra-module анализаторе графа вызовов (`moduleEdges`), полностью разрешая кейс `real-micro-xds` в истинный вердикт **`EXPLOITABLE`** без case-specific хардкода.

---

## 2. Архитектурный дизайн

### 2.1. Разрешение локальных method values и переменных функций (Механизм A)

В `internal/goanalysis/source.go` при обходе вызовов `call, ok := n.(*ast.CallExpr)`:
1. Если `obj := calleeObject(info, call.Fun)` не является `*types.Func`, но `call.Fun` является идентификатором (`*ast.Ident`) или `obj` является локальной переменной (`*types.Var`):
   - Проверяется тип переменной: `obj.Type().Underlying()` является `*types.Signature`.
   - Производится поиск всех выражений, присваиваемых данной переменной внутри объемлющей функции `encDecl` с помощью `assignRHS(info, encDecl, obj)`.
2. Для каждого правого выражения (RHS):
   - Если RHS является `*ast.SelectorExpr` (например, `filterBuilder.ParseFilterConfig`):
     - Извлекается объект селектора: через `info.Selection[rhs]` (для method values) или `info.ObjectOf(rhs.Sel)`.
     - Если объект является `*types.Func`:
       - Вычисляется полный квалифицированный ключ вызываемой функции/метода.
       - Добавляется ребро: `addEdge(caller, callee)`.
       - Если ресивер метода является интерфейсом (`*types.Interface`):
         - Метод регистрируется в `ifaceSites[named][fn.Name()]`, чтобы механизм связывания интерфейсов (`ifaceSites`) связал интерфейсный метод со всеми конкретными реализациями в модуле (включая `rbac.builder.ParseFilterConfig`).
   - Если RHS является `*ast.Ident` (например, `f := concreteFunc`):
     - `info.ObjectOf(rhs)` разрешается в `*types.Func`, и добавляется прямое ребро.
3. Если хотя бы одно присваивание успешно разрешилось в целевую функцию/метод:
   - Данный вызов считается разрешённым и **не** помечает вызывающего как `opaqueCaller`.

### 2.2. Диспетчеризация полей структур с сигнатурой функций (Механизм B)

В Go широко распространён паттерн передачи зависимостей и колбэков через функциональные поля структур (`Authority{getChannelForADS: c.getChannelForADS}`, `Server{Handler: ...}`, `Watcher{OnUpdate: ...}`):

1. **Сбор привязок функциональных полей модуля**:
   При обходе синтаксиса пакетов модуля собирается карта:
   ```go
   // "pkg.TypeName.FieldName" -> []calleeTarget
   fieldFuncs := map[string][]calleeTarget{}
   ```
   Источники привязок:
   - **Композитные литералы** `&Type{Field: expr}` и `Type{Field: expr}`:
     Для элементов вида `Key: Ident`, `Value: expr`: если поле `Field` имеет тип `*types.Signature`:
     - Если `Value` — `*ast.SelectorExpr` (method value `recv.Method`):
       Извлекается метод `*types.Func` через `info.Selection` или `info.ObjectOf`.
     - Если `Value` — `*ast.Ident` (функция `pkg.Func` или `localFunc`):
       Извлекается `*types.Func`.
     - Сохраняется привязка `fieldFuncs[fieldKey] = append(..., target)`.
   - **Операторы присваивания** `s.Field = expr`:
     Аналогично извлекается целевой метод/функция.

2. **Разрешение вызовов полей**:
   При обнаружении вызова `s.Field(...)` (где `call.Fun` — `*ast.SelectorExpr`, а селектор указывает на `*types.Var` с типом `*types.Signature`):
   - Формируется ключ поля `fieldKey := structFieldKey(fieldVar)`.
   - Из карты `fieldFuncs[fieldKey]` извлекаются все зарегистрированные целевые функции.
   - Для каждой целевой функции добавляется ребро `addEdge(caller, targetCallee)`.
   - Если целевой метод является интерфейсным, он добавляется в `ifaceSites`.
   - Вызывающий **не** помечается как `opaqueCaller`, если для поля найдены статические реализации.

### 2.3. Пакетные функциональные переменные (Механизм C)

Для переменных уровня пакета вида `var newServer = grpc.NewServer` или инициализируемых в `init()`:
- `assignRHS` расширяется для поиска инициализаций переменных уровня пакета в `File.Decls` пакета (включая `ValueSpec.Values` и присваивания внутри функций пакета).
- Вызов пакетной переменной `varFn(...)` связывается с присвоенными функциями.

### 2.4. Сохранение точности и чистота неопределённостей

- Если вызов функциональной переменной / поля структуры не имеет ни одной статической привязки в коде модуля (например, передаётся извне модуля или вычисляется динамически через рефлексию), вызов по-прежнему считается **неразрешимым** и помечается в `opaqueCallers`.
- Неизменность принципа: отсутствие пути при наличии достижимого `opaqueCaller` приводит к `UNKNOWN` (честное ограничение). Но при обнаружении доказанной статической цепочки до синка факт наличия других несвязанных opaque-вызовов не аннулирует найденную положительную цепочку достижимости (`ModuleReachable`).

---

## 3. Соответствие правилам проекта

1. **Генеральность (`docs/agent-rules/generality.md`)**:
   - Никаких строк `"google.golang.org/grpc"`, `"xds"`, `"authority"`, `"getChannelForADS"`, `"rbac"` в `internal/goanalysis`!
   - Механизмы A, B и C работают исключительно по AST и типам Go (`go/ast`, `go/types`): `*ast.AssignStmt`, `*ast.SelectorExpr`, `*ast.CompositeLit`, `*types.Var`, `*types.Signature`.
2. **Безопасность (`docs/agent-rules/security.md`)**:
   - `false-safe = 0`. Добавление рёбер достижимости может переводить `UNKNOWN` в `EXPLOITABLE` (положительное доказательство) или оставлять `UNKNOWN`, но не создаёт ложных `NO_EXPLOIT_PATH_FOUND`.
3. **Наблюдаемость и отчётность (`docs/agent-rules/observability.md`)**:
   - Найденная цепочка шагов (25 узлов) сохраняется в `c.EvidenceGraph.ModuleReachable` и документируется в структурированном evidence `source index: module-internal call chain` с указанием всех промежуточных вызовов.

---

## 4. План приёмки и верификации

1. **Модульные тесты (`internal/goanalysis/source_test.go`)**:
   - Тест на вызов локального method value: `m := recv.Method; m()`.
   - Тест на вызов поля структуры с func-сигнатурой: `s := &Struct{Fn: obj.Method}; s.Fn()`.
   - Тест на интерфейсную диспетчеризацию через переменную: `var f = iface.Method; f()`.
2. **Интеграционный тест кейса `real-micro-xds`**:
   - `ModuleInternalReach` строит полную цепочку от `xds.NewGRPCServer` / `GRPCServer.Serve` до `rbac.parseConfig`.
   - `opaque` не блокирует найденную цепочку.
3. **Корпусный тест `eval/corpus-real.json`**:
   - Запуск `izyan eval --corpus eval/corpus-real.json`.
   - `real-micro-xds` переходит из `INCONCLUSIVE` в **`EXPLOITABLE`**.
   - Общие метрики корпуса:
     - Total: 38
     - `EXPLOITABLE`: 18 (+1)
     - `CLEARED`: 20 (`NOT_AFFECTED` + `NO_EXPLOIT_PATH_FOUND`)
     - `INCONCLUSIVE`: 0 (-1)
     - `false-safe`: 0
     - 100% корпуса полностью разрешено!
4. **Синхронизация документации**:
   - Удаление пункта B24 из §2 в `docs/dev/gap-analysis.md`.
   - Обновление таблицы результатов в `eval/README.md`.
