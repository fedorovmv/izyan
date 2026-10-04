# Внутренняя непрямая диспетчеризация (B24) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Реализовать статическое разрешение локальных method values, функциональных переменных и функциональных полей структур в intra-module анализе графа вызовов (`internal/goanalysis/source.go`), доведя кейс `real-micro-xds` до истинного вердикта `EXPLOITABLE` и закрыв пункт бэклога B24.

**Architecture:** В `moduleEdges` расширяется анализ вызовов: вызовы локальных функциональных переменных разрешаются через поиск присваиваний (`assignRHS`), вызовы функциональных полей структур разрешаются через карту присваиваний полям в композитных литералах и операторах присваивания модуля. Вызовы связываются с целевыми функциями/интерфейсными методами без маркировки `opaqueCaller`, позволяя BFS находить полные статические цепочки.

**Tech Stack:** Go standard library (`go/ast`, `go/types`, `go/token`), `golang.org/x/tools/go/packages`, `internal/goanalysis`, `internal/domain`.

## Global Constraints

- Никаких case-specific строк или идентификаторов анализируемых продуктов (`google.golang.org/grpc`, `xds`, `authority`, `rbac`) в `internal/goanalysis/` (`docs/agent-rules/generality.md`).
- Safety invariant: safe negative verdicts require a verified falsifier on a mandatory condition (`false-safe = 0`).
- Отрицательные вердикты не фабрикуются; положительная цепочка достижимости формирует истинный `EXPLOITABLE`.
- Все тесты и команды должны проходить `gofmt`, `go vet ./...`, `go test ./...`.
- По завершении пункт B24 удаляется из §2 в `docs/dev/gap-analysis.md`, а таблица в `eval/README.md` обновляется.

---

### Task 1: Разрешение вызовов локальных method values и переменных функций (Механизм A)

**Files:**
- Modify: `internal/goanalysis/source.go`
- Test: `internal/goanalysis/source_test.go`

**Interfaces:**
- Consumes: `assignRHS(info, encDecl, obj)` из `internal/goanalysis/dispatch.go`.
- Produces: Добавление рёбер `addEdge(caller, callee)` и регистрация в `ifaceSites` для локально присвоенных method values и функций.

- [ ] **Step 1: Написать падающий тест для вызова локального method value**

Создать тест в `internal/goanalysis/source_test.go`, проверяющий, что вызов `m := r.Method; m()` через локальную переменную корректно связывается с целевым методом ресивера (и через интерфейс — с его реализациями) и не помечается как `opaque`:

```go
func TestModuleEdges_LocalMethodValue(t *testing.T) {
	src := `package testpkg

type Greeter interface {
	Greet() string
}

type greeterImpl struct{}

func (greeterImpl) Greet() string { return "hello" }

func Run(g Greeter) string {
	fn := g.Greet
	return fn()
}
`
	// Тестирование построения рёбер moduleEdges: Run -> Greeter.Greet -> greeterImpl.Greet
}
```

- [ ] **Step 2: Запустить тест и зафиксировать RED**

Run: `go test -v -run TestModuleEdges_LocalMethodValue ./internal/goanalysis`
Expected: FAIL (Greeter.Greet не вызывается или помечается opaque).

- [ ] **Step 3: Реализовать разрешение локальных method values в `moduleEdges`**

В `internal/goanalysis/source.go` в цикле `ast.Inspect`:
Когда `calleeObject(info, call.Fun)` возвращает `*types.Var` (или `call.Fun` — `*ast.Ident`), если тип переменной является `*types.Signature`:
1. Вызвать `assignRHS(info, encDecl, obj)`.
2. Для каждого RHS выражения:
   - Если `*ast.SelectorExpr`: извлечь `*types.Func` через `info.Selection` или `info.ObjectOf(sel.Sel)`.
   - Если `*ast.Ident`: извлечь `*types.Func` через `info.ObjectOf(id)`.
   - Добавить ребро `addEdge(pkg.PkgPath+"."+caller, calleeKey)`.
   - Если ресивер — интерфейс, добавить в `ifaceSites[named][fn.Name()]`.
3. Если хотя бы одно ребро добавлено, флаг `resolved = true`, и вызывающий не добавляется в `opaqueCallers`.

- [ ] **Step 4: Запустить тест и зафиксировать GREEN**

Run: `go test -v -run TestModuleEdges_LocalMethodValue ./internal/goanalysis`
Expected: PASS.

- [ ] **Step 5: Коммит**

```bash
git add internal/goanalysis/source.go internal/goanalysis/source_test.go
git commit -m "feat(goanalysis): resolve local method values and func variable calls in moduleEdges"
```

---

### Task 2: Разрешение вызовов функциональных полей структур (Механизм B)

**Files:**
- Modify: `internal/goanalysis/source.go`
- Test: `internal/goanalysis/source_test.go`

**Interfaces:**
- Consumes: `*ast.CompositeLit`, `*ast.AssignStmt`, `*types.Var`, `*types.Signature`.
- Produces: Карта `fieldFuncs` структуры в модуле и связывание `s.Field(...)` с присвоенными методами/функциями.

- [ ] **Step 1: Написать падающий тест для диспетчеризации полей структур**

Создать тест в `internal/goanalysis/source_test.go`, где структура содержит функциональное поле `Fn func()`, инициализируемое method value `&Wrapper{Fn: obj.TargetMethod}`, и метод структуры вызывает `w.Fn()`:

```go
func TestModuleEdges_StructFieldFunc(t *testing.T) {
	src := `package testpkg

type Target struct{}
func (Target) Action() {}

type Runner struct {
	runFn func()
}

func NewRunner(t *Target) *Runner {
	return &Runner{runFn: t.Action}
}

func (r *Runner) Execute() {
	r.runFn()
}
`
	// Проверяем, что Execute -> Target.Action есть в edges
}
```

- [ ] **Step 2: Запустить тест и зафиксировать RED**

Run: `go test -v -run TestModuleEdges_StructFieldFunc ./internal/goanalysis`
Expected: FAIL (`Execute -> Target.Action` отсутствует).

- [ ] **Step 3: Реализовать сбор и связывание функциональных полей в `moduleEdges`**

В `internal/goanalysis/source.go`:
1. Ввести сбор `structFieldFuncs map[string][]types.Object`:
   - В композитных литералах `&T{Field: expr}`: если поле имеет тип `*types.Signature`, извлечь целевую функцию/метод из `expr` (`*ast.SelectorExpr` method value или `*ast.Ident` func).
   - В операторах присваивания `x.Field = expr`: аналогично.
2. При вызове `call`:
   - Если `call.Fun` — `*ast.SelectorExpr`, и `sel` указывает на поле структуры `*types.Var` с типом `*types.Signature`:
   - Найти кандидатов в `structFieldFuncs[fieldKey]`.
   - Для каждого кандидата добавить ребро `addEdge(caller, targetCallee)`.
   - Если кандидат — интерфейсный метод, зарегистрировать в `ifaceSites`.
   - Если кандидаты найдены, не помечать `caller` как `opaqueCaller`.

- [ ] **Step 4: Запустить тест и зафиксировать GREEN**

Run: `go test -v -run TestModuleEdges_StructFieldFunc ./internal/goanalysis`
Expected: PASS.

- [ ] **Step 5: Коммит**

```bash
git add internal/goanalysis/source.go internal/goanalysis/source_test.go
git commit -m "feat(goanalysis): resolve struct field func callback dispatch in moduleEdges"
```

---

### Task 3: Интеграционный тест кейса `real-micro-xds` и очистка отладочного кода

**Files:**
- Modify: `internal/goanalysis/dispatch_test.go`
- Test: `internal/goanalysis/dispatch_test.go`

**Interfaces:**
- Consumes: `ModuleInternalReach` из `internal/goanalysis/source.go`.
- Produces: Доказанная цепочка вызовов от `GRPCServer.Serve` до `rbac.parseConfig` без симуляций.

- [ ] **Step 1: Заменить отладочный `TestDebugMicroXDS` на канонический интеграционный тест**

В `internal/goanalysis/dispatch_test.go`:
Очистить все симуляции и временные логи. Написать чистый интеграционный тест:
`TestModuleInternalReach_XDS(t *testing.T)`:
- Загружает `real-micro-xds`.
- Вызывает `ix.ModuleInternalReach(ctx, "google.golang.org/grpc", entries, subjects)`.
- Утверждает, что `reach["google.golang.org/grpc/internal/xds/httpfilter/rbac.parseConfig"]` не nil и имеет длину $\ge 15$ шагов.

- [ ] **Step 2: Запустить интеграционный тест**

Run: `go test -v -run TestModuleInternalReach_XDS ./internal/goanalysis`
Expected: PASS (цепочка найдена реальным анализом).

- [ ] **Step 3: Проверить запуск CLI eval на кейсе `real-micro-xds`**

Run: `go run ./cmd/izyan eval --corpus eval/corpus-real.json --case real-micro-xds`
Expected: Вердикт `EXPLOITABLE` (ранее был `INCONCLUSIVE`).

- [ ] **Step 4: Коммит**

```bash
git add internal/goanalysis/dispatch_test.go
git commit -m "test(goanalysis): add integration test for xds reachability without simulation"
```

---

### Task 4: Корпусная валидация, синхронизация документации и закрытие B24

**Files:**
- Modify: `docs/dev/gap-analysis.md` (удаление B24 из §2)
- Modify: `eval/README.md` (обновление метрик корпуса: 18 EXPLOITABLE, 20 CLEARED, 0 INCONCLUSIVE)

- [ ] **Step 1: Запустить полный корпус из 38 кейсов**

Run: `go run ./cmd/izyan eval --corpus eval/corpus-real.json -j 4`
Expected:
`cases=38 errors=0 expect pass=38 fail=0 false-safe=0 inconclusive=0`
`18 EXPLOITABLE, 20 CLEARED`.

- [ ] **Step 2: Запустить проверки качества кода**

Run:
```bash
gofmt -w internal/
go vet ./...
go test ./...
```
Expected: PASS без ошибок и предупреждений.

- [ ] **Step 3: Синхронизировать документацию**

В `docs/dev/gap-analysis.md`:
- Удалить строку B24 из §2.
- Отметить закрытие B24 в таблице §1.

В `eval/README.md`:
- Обновить счетчики корпуса: 38 кейсов, 18 EXPLOITABLE, 20 CLEARED, 0 INCONCLUSIVE.

- [ ] **Step 4: Коммит закрытия задачи**

```bash
git add docs/dev/gap-analysis.md eval/README.md
git commit -m "docs: close B24 and update corpus baseline to 100% resolved (0 inconclusive)"
```
