# Локальное основание отклонения CVE — план исполнения исследования

> Для исполнителя: использовать `superpowers:executing-plans` и выполнять
> задачи последовательно. Не запускать этот план только из-за наличия
> файла: при его сохранении пользователь запросил лишь запись документов.

**Статус:** документы сохранены; исследование не запускалось.

**Внешний пул кейсов:** помимо jose2go-контролей ниже существует приватный
реестр реальных кейсов отклонения на продуктовых снапшотах — вне
репозитория, резолвится через `VA_RESEARCH_ROOT` (см. §7 спецификации).
Использовать его кейсы как дополнительные якоря для оценки классов
оснований (`GATE-FEATURE`, `SYM-ABSENT`, `CFG-EXPR`, `TRUST`); в tracked
артефакты переносить только публичные advisory ID и обобщённые выводы.

**Goal:** воспроизводимо проверить основание по типу ключа в `jose2go`,
сравнить его с сигналами govulncheck и подготовить доказательное досье.

**Architecture:** существующий eval-harness материализует четыре
исследовательских продукта. Исходники и контрольные тесты проверяют
гипотезу отдельно от authoritative analyzer verdict. Существующие
deterministic и LLM adapters запускаются без нового checker.

**Tech Stack:** Go, существующий `cmd/analyzer`, govulncheck, shell, jq.

**Spec:**
[`llm-dismissal-research-spec.md`](../specs/llm-dismissal-research-spec.md).
Прочитать до исполнения, вместе с главными инвариантами `AGENTS.md`.

## Global Constraints

- Результат — исследование и досье, не production-checker. Не добавлять
  evaluators, condition kinds, falsifiers или правила negative verification.
- Изменения только в исследовательских продуктах, research corpus,
  ground-truth документах и связанных документах/index/backlog.
- Не менять `internal/`, `cmd/analyzer`, `knowledge.json`, существующие
  `expect` и правила подсчёта метрик.
- Не создавать ветку и не коммитить без отдельного запроса.
- Рабочее дерево содержит чужие/параллельные незакоммиченные изменения:
  не откатывать, не форматировать чужие файлы, не перезаписывать документы
  целиком. Перечитать файл, если он изменился после проверки.
- Правки через `apply_patch`; временные результаты только в `eval/.gen/`.
- Не запускать большой `p2c` или исчерпывающий CPU DoS.
- Не создавать credentials, не выводить API keys и приватные пути.
- Автоматическое снятие не обязательно для завершения исследования;
  открытые обязательства должны оставаться открытыми.

## Review Focus

- `[]byte` на границе может отличаться от фактического ключа после callback:
  callback-вариант обязан успешно пройти PBES2-контроль.
- Deployment-dependent ключ не допускает универсального safe-вывода:
  dynamic-вариант проверяется в обоих режимах.
- Parser error не является достижением type gate: отдельный malformed
  контроль проверяет другую причину отказа.
- Calls из `_test.go` не должны создавать ложный production baseline:
  standalone govulncheck запускать с `-test=false`; охват test-only paths
  в исходных evidence анализатора отмечать отдельно.
- Round trip и найденный guard не доказывают completeness или absence of
  exploitation: source audit, necessity и coverage имеют отдельные разделы.

## Задача 0. Подготовить окружение и снять исходное состояние

**Read:** `AGENTS.md`, `docs/agent-rules/testing.md`, `security.md`,
`generality.md`, `docs-sync.md` из того же каталога правил.

- [ ] Выполнить `git status --short` и `git diff --stat`; запомнить чужие
  изменения до собственных патчей.
- [ ] В одной shell-сессии установить переменные и создать каталог:

```bash
RUN_ROOT="$PWD/eval/.gen/jose-research"
mkdir -p "$RUN_ROOT"
GV="$(command -v govulncheck || true)"
if [ -z "$GV" ]; then
  GV="$(go env GOPATH)/bin/govulncheck"
fi
test -x "$GV" || exit 1
export PATH="$(dirname "$GV"):$PATH"

go version > "$RUN_ROOT/go-version.txt"
"$GV" -version > "$RUN_ROOT/govulncheck-version.txt"
git rev-parse HEAD > "$RUN_ROOT/analyzer-revision.txt"
git diff --stat > "$RUN_ROOT/worktree-stat.txt"
go build -o "$RUN_ROOT/analyzer" ./cmd/analyzer
```

При новой shell-сессии заново установить `RUN_ROOT`, `GV` и `PATH`.
Бинарь собирать после сохранения исходного состояния и не пересобирать
между сравниваемыми прогонами. Если source tree изменился параллельно,
сохранить факт: сравнивается один уже собранный бинарь, а не новый HEAD.

**Expected:** исполняемый analyzer и версии инструментов сохранены.
При подготовке плана обнаружены Go `1.26.1` и govulncheck `1.8.0`;
записать фактические версии, не требовать их совпадения с этой заметкой.
Не сравнивать новую серию с прежним `1.1.4` как с одинаковым baseline.

**Stop:** отсутствует инструмент или не собирается analyzer — записать
ошибку; не устанавливать другую версию автоматически и не чинить
несвязанные проблемы.

## Задача 1. Сохранить идеи, план и навигацию

Эта задача выполнена при сохранении документов; при исполнении только
проверить наличие и актуальность ссылок.

- [x] Создать `docs/dev/specs/llm-dismissal-research-spec.md` с восемью
  направлениями, выбранным гибридом, инвариантами и границами исследования.
- [x] Создать этот план с файлами, командами, контролями и stop conditions.
- [x] Добавить две ссылки в `docs/INDEX.md`.
- [x] Добавить исследовательский пункт `B27` в §2
  `docs/dev/current/gap-analysis.md`, не изменяя `B26`.

**Expected:** спецификация сохраняет решения и идеи; план определяет
исполнение. Ничего в этих документах не утверждает, что hypothesis
проверена или что checker уже реализован.

## Задача 2. Проверить источник гипотезы

**Input:** `eval/advisories/real/GO-2023-2409.json`, текущий
`eval/products/jose-decrypt/main.go`, dependency/fixed source.

**Output:** исходники, diff, инвентарь relevant calls и таблица source audit
в `$RUN_ROOT/source/`; её фактические выводы затем идут в досье задачи 5.

- [ ] Скачать fixed pins вне корневого module:

```bash
mkdir -p "$RUN_ROOT/source"
(
  cd "$RUN_ROOT/source"
  go mod download -json github.com/dvsekhvalnov/jose2go@v1.5.0 \
    > vulnerable-module.json
  go mod download -json \
    github.com/dvsekhvalnov/jose2go@v1.5.1-0.20231206184617-48ba0b76bc88 \
    > fixed-module.json
)
DEP_DIR="$(jq -r '.Dir' "$RUN_ROOT/source/vulnerable-module.json")"
FIXED_DIR="$(jq -r '.Dir' "$RUN_ROOT/source/fixed-module.json")"
test -d "$DEP_DIR" && test -d "$FIXED_DIR" || exit 1
```

- [ ] Прочитать полностью advisory и следующие vulnerable-файлы:
  `jose.go`, `pbse2_hmac_aeskw.go`, `compact/compact.go`, `kdf/pbkdf2.go`.
- [ ] Сохранить diff; exit code `1` означает различия, `>1` — ошибка:

```bash
diff -u "$DEP_DIR/pbse2_hmac_aeskw.go" \
  "$FIXED_DIR/pbse2_hmac_aeskw.go" \
  > "$RUN_ROOT/source/pbes2.diff"
DIFF_STATUS=$?
test "$DIFF_STATUS" -le 1 || exit "$DIFF_STATUS"

rg -n 'DerivePBKDF2|RegisterJwa|retrieveActualKey|Unwrap|WrapNewKey' \
  "$DEP_DIR" --glob '*.go' --glob '!**/*_test.go' \
  > "$RUN_ROOT/source/call-inventory.txt"

jq -r '.references[] | select(.type == "FIX") | .url' \
  eval/advisories/real/GO-2023-2409.json \
  > "$RUN_ROOT/source/fix-references.txt"
```

- [ ] Прочитать изменения каждого заявленного FIX artifact. Недоступный
  artifact отметить как незакрытое обязательство, не заменить выводом
  «локальный diff выглядит достаточным».
- [ ] Проверить всю цепочку `Decode -> DecodeBytes -> decrypt ->
  retrieveActualKey -> Unwrap -> DerivePBKDF2` и зафиксировать ответы:

| Вопрос | Что искать и записывать |
|---|---|
| Как выбирается JWE? | Ветка по числу частей, parser и early errors |
| Как разрешается фактический ключ? | Возврат исходного ключа или вызов callback |
| Какой type gate предшествует derivation? | Type assertion и вся surviving branch |
| Есть ли преобразование `[]byte -> string`? | Все assignments, returns и casts вдоль key flow |
| Какие ещё derivation sites relevant? | Все совпадения, включая encryption и другие algorithms |
| Что именно исправляет FIX? | Bounds, locations, affected operation и связанные изменения |
| Что передаёт текущий `real-jose-decrypt`? | Тип, источник и полный набор присваиваний ключа |

- [ ] Записать source paths относительно dependency root, версии,
  строки, module sums и hashes просмотренных source artifacts. Для hashes
  на macOS использовать `shasum -a 256`; не переносить приватный cache path
  в tracked документ.

**Expected:** отдельно сформулированы necessity условия и product-specific
неприменимость; необоснованные части явно отмечены `OPEN`.

**Stop for redesign:** исходники не соответствуют цепочке или обнаружен
неразрешённый relevant path — не подбирать другой CVE и не реализовывать
checker. Досье продолжить с конкретным открытым обязательством.

## Задача 3. Создать четыре продукта и исполняемые контроли

**Create:** `main.go` и `main_test.go` в каждом каталоге:

```text
eval/products/research-jose-bytes/
eval/products/research-jose-string/
eval/products/research-jose-callback/
eval/products/research-jose-dynamic/
```

**Create:** `eval/corpus-jose-research.json`.

Не создавать `go.mod`/`go.sum` в product directories. Не менять исходный
`eval/products/jose-decrypt/main.go`.

### Шаг 3.1. Создать product entrypoint и RED-заготовки

- [ ] В каждый `main.go` поместить следующий полный entrypoint:

```go
package main

import (
	"io"
	"log"
	"net/http"

	jose "github.com/dvsekhvalnov/jose2go"
)

const researchPassphrase = "research-passphrase"

func keyForDecode() any {
	return nil
}

func intake(token string) (string, error) {
	payload, _, err := jose.Decode(token, keyForDecode())
	if err != nil {
		return "", err
	}
	return payload, nil
}

func handleIntake(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20))
	if err != nil {
		http.Error(writer, "read body", http.StatusBadRequest)
		return
	}
	if _, err := intake(string(body)); err != nil {
		http.Error(writer, "token rejected", http.StatusUnauthorized)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func main() {
	http.HandleFunc("/intake", handleIntake)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

`research-passphrase` — синтетическая fixture-строка, не настоящий secret.
Не запускать сервер для этих проверок: тесты вызывают `intake` напрямую.

### Шаг 3.2. Написать тесты до окончательных key implementations

- [ ] В каждом `main_test.go` написать тестовый файл ниже. Единственное
  различие — тело `expectedSuccess` по таблице после блока.

```go
package main

import (
	"strings"
	"testing"

	jose "github.com/dvsekhvalnov/jose2go"
)

func expectedSuccess(mode string) bool {
	return false
}

func TestKeyShape(t *testing.T) {
	for _, mode := range []string{"bytes", "string"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("RESEARCH_KEY_MODE", mode)
			key := keyForDecode()
			if callback, ok := key.(func(map[string]interface{}, string) interface{}); ok {
				key = callback(nil, "")
			}
			if expectedSuccess(mode) {
				if _, ok := key.(string); !ok {
					t.Fatalf("expected string key, got %T", key)
				}
				return
			}
			if _, ok := key.([]byte); !ok {
				t.Fatalf("expected byte slice key, got %T", key)
			}
		})
	}
}

func TestPBES2TypeGate(t *testing.T) {
	algorithms := []string{
		jose.PBES2_HS256_A128KW,
		jose.PBES2_HS384_A192KW,
		jose.PBES2_HS512_A256KW,
	}
	for _, algorithm := range algorithms {
		for _, mode := range []string{"bytes", "string"} {
			t.Run(algorithm+"/"+mode, func(t *testing.T) {
				t.Setenv("RESEARCH_KEY_MODE", mode)
				token, err := jose.Encrypt(
					"proof-payload", algorithm, jose.A256GCM, researchPassphrase,
				)
				if err != nil {
					t.Fatal(err)
				}
				payload, err := intake(token)
				if expectedSuccess(mode) {
					if err != nil || payload != "proof-payload" {
						t.Fatalf("payload=%q err=%v", payload, err)
					}
					return
				}
				if err == nil || !strings.Contains(
					err.Error(), "expected key to be 'string' array",
				) {
					t.Fatalf("expected PBES2 key-type rejection, got %v", err)
				}
			})
		}
	}
}

func TestMalformedTokenIsNotTypeGate(t *testing.T) {
	_, err := intake("invalid")
	if err == nil || strings.Contains(err.Error(), "expected key to be 'string' array") {
		t.Fatalf("expected parser rejection unrelated to key type, got %v", err)
	}
}
```

Тело `expectedSuccess`:

| Product suffix | Точное тело |
|---|---|
| bytes | `return false` |
| string | `return true` |
| callback | `return true` |
| dynamic | `return mode == "string"` |

Не использовать `t.Parallel`: тесты меняют environment. Assertions на
ошибку здесь служат branch control, а не машинным proof of exploit absence.

### Шаг 3.3. Создать informational corpus и подтвердить RED

- [ ] Создать следующий полный `eval/corpus-jose-research.json`:

```json
{
  "cases": [
    {
      "id": "research-jose-bytes",
      "vuln": "GO-2023-2409",
      "vuln_file": "advisories/real/GO-2023-2409.json",
      "product": "products/research-jose-bytes",
      "module": "example.com/research-jose-bytes",
      "deps": {"github.com/dvsekhvalnov/jose2go": "v1.5.0"}
    },
    {
      "id": "research-jose-string",
      "vuln": "GO-2023-2409",
      "vuln_file": "advisories/real/GO-2023-2409.json",
      "product": "products/research-jose-string",
      "module": "example.com/research-jose-string",
      "deps": {"github.com/dvsekhvalnov/jose2go": "v1.5.0"}
    },
    {
      "id": "research-jose-callback",
      "vuln": "GO-2023-2409",
      "vuln_file": "advisories/real/GO-2023-2409.json",
      "product": "products/research-jose-callback",
      "module": "example.com/research-jose-callback",
      "deps": {"github.com/dvsekhvalnov/jose2go": "v1.5.0"}
    },
    {
      "id": "research-jose-dynamic",
      "vuln": "GO-2023-2409",
      "vuln_file": "advisories/real/GO-2023-2409.json",
      "product": "products/research-jose-dynamic",
      "module": "example.com/research-jose-dynamic",
      "deps": {"github.com/dvsekhvalnov/jose2go": "v1.5.0"}
    }
  ]
}
```

Не добавлять `expect`, manual root causes или exploit model. Не навязывать
анализатору hypothesis или desired verdict.

- [ ] Отформатировать новые Go-файлы и материализовать:

```bash
gofmt -w eval/products/research-jose-{bytes,string,callback,dynamic}/*.go
"$RUN_ROOT/analyzer" eval \
  --corpus eval/corpus-jose-research.json \
  --case-dir "$RUN_ROOT/bootstrap-cases" \
  --json "$RUN_ROOT/bootstrap.json"
```

- [ ] Запустить RED-контроль:

```bash
(
  cd eval/.gen/research-jose-bytes
  go test -run TestKeyShape -count=1 ./...
)
```

**Expected:** тест падает из-за `nil`, не из-за compile error.

### Шаг 3.4. Реализовать варианты и подтвердить GREEN

- [ ] Заменить только `keyForDecode` следующими реализациями.

**bytes:**

```go
func keyForDecode() any {
	return []byte(researchPassphrase)
}
```

**string:**

```go
func keyForDecode() any {
	return researchPassphrase
}
```

**callback:**

```go
func keyForDecode() any {
	return func(headers map[string]interface{}, payload string) interface{} {
		return researchPassphrase
	}
}
```

**dynamic:** добавить `os` в imports этого `main.go`.

```go
func keyForDecode() any {
	if os.Getenv("RESEARCH_KEY_MODE") == "string" {
		return researchPassphrase
	}
	return []byte(researchPassphrase)
}
```

- [ ] Повторно выполнить gofmt и материализацию из шага 3.3, заменив
  bootstrap output/case-dir suffix на `green-bootstrap`, чтобы сохранить RED.
- [ ] Запустить тесты generated modules:

```bash
for kind in bytes string callback dynamic; do
  (
    cd "eval/.gen/research-jose-$kind"
    go vet ./...
    go test -count=1 -timeout=30s ./...
  ) || exit 1
done
```

**Expected:** все тесты проходят; валидный PBES2 token отвергается bytes
по нужному type gate, принимается string/callback, dynamic показывает
оба режима. Это проверка отличия branch behavior, не исполнение DoS.

**Stop:** не ослаблять assertions ради GREEN. При несовпадении вернуться
к source audit и записать опровергнутую предпосылку.

## Задача 4. Получить baseline и результаты существующего pipeline

**Input:** окончательные GREEN-файлы и informational research corpus.

**Output:** сырые streams, eval JSON/Markdown и per-case report.json в
`$RUN_ROOT`; никаких изменений adapters или knowledge base.

### Шаг 4.1. Детерминистический прогон и standalone baseline

- [ ] Убрать test environment override из shell, если он был задан:

```bash
unset RESEARCH_KEY_MODE
"$RUN_ROOT/analyzer" eval \
  --corpus eval/corpus-jose-research.json \
  --case-dir "$RUN_ROOT/deterministic-cases" \
  --out "$RUN_ROOT/deterministic.md" \
  --json "$RUN_ROOT/deterministic.json"

for kind in bytes string callback dynamic; do
  "$GV" -C "$PWD/eval/.gen/research-jose-$kind" \
    -json -mode source -scan symbol -test=false ./... \
    > "$RUN_ROOT/govulncheck-$kind.json" \
    2> "$RUN_ROOT/govulncheck-$kind.stderr" || exit 1
done
"$GV" -version > "$RUN_ROOT/govulncheck-version-after.txt"
```

- [ ] Выделить findings для каждого stream; пример bytes:

```bash
jq -s '[.[] | .finding? | select(.osv == "GO-2023-2409")]' \
  "$RUN_ROOT/govulncheck-bytes.json"
```

- [ ] Классификацию baseline брать из eval JSON и сверить с raw finding:
  function-level trace против package-level. Если baseline silent,
  not-in-db или error, этот вариант не доказывает снятие сигнала.
- [ ] Проверить version/DB timestamp до и после серии и OSV object для
  этого advisory в streams. При изменении повторить всю сравнительную
  серию один раз. Если база снова меняется, явно назвать сравнение
  несопоставимым, не зацикливать прогоны.
- [ ] Проверить per-case `report.json`: для любого safe-verdict назвать
  mandatory claim, falsifier, NV status и evidence scope. Не считать
  информационный verdict доказанным только по его имени.

**Expected:** результат каждой программы известен независимо от желаемого
исхода. `false-safe=0` research corpus без `expect` не имеет достаточного
oracle и не является stop-критерием безопасности этого исследования.

### Шаг 4.2. Существующий LLM pipeline без подсказанной модели

- [ ] Использовать только явно предоставленный `LLM_ENV`:

```bash
test -n "${LLM_ENV:-}" || exit 1
test -f "$LLM_ENV" || exit 1

LLM_ENABLED=1 LLM_BUILD_MAX_RETRIES=0 \
  "$RUN_ROOT/analyzer" eval \
  --with-llm \
  --llm-env "$LLM_ENV" \
  --corpus eval/corpus-jose-research.json \
  --case-dir "$RUN_ROOT/llm-1-cases" \
  --out "$RUN_ROOT/llm-1.md" \
  --json "$RUN_ROOT/llm-1.json"
```

Без конфигурации не создавать credentials. Отметить LLM-серию как
`NOT_RUN: configuration unavailable`; source audit и досье всё равно
можно завершить, но вклад LLM останется неизмеренным.

- [ ] Не добавлять manual model, root causes или prompts с готовой
  key-type hypothesis. Не менять adapters, prompts, budgets ради успеха.
- [ ] В per-case `report.json` прочитать `exploit`, `hypotheses`, `claims`,
  `reviews`, `workflow.usage.llm_calls`; зафиксировать реальные model IDs
  и parameters без API key и приватных endpoint/path.
- [ ] Для каждого продукта записать наличие condition, key mapping,
  учёт callback, сохранение deployment-зависимости, источники, coverage
  obligations и итоговый verdict.
- [ ] Если первый прогон предложил relevant source-grounded hypothesis
  и не снял ошибочно string/callback/dynamic, выполнить ещё два таких же
  прогона с suffix `llm-2` и `llm-3`. Иначе остановить повторения.

Максимум — три серии. При подготовке плана текущий лимит — 32 calls на
case; не увеличивать его. Если реальный binary имеет другой лимит,
записать его, не патчить код. Тем самым первоначальный верхний предел
полного эксперимента при текущем лимите — 384 LLM calls.

**Expected:** различимы вклад LLM, ручного source audit и уже существующего
deterministic pipeline. Неудача существующих adapters не означает
доказанную невозможность всей идеи LLM-assisted proof.

## Задача 5. Оформить досье и завершить исследование

**Create:** `eval/ground-truth/research-jose-key-type.md`.

**Modify:** `eval/ground-truth/real-jose-decrypt.md`, `eval/README.md`,
исследовательский spec/plan по статусу и §2 backlog по завершению.

- [ ] Заполнить досье фактическими результатами по этой структуре:

1. Предмет: advisory, versions, фиксированный дефект, не все JOSE flaws.
2. Necessity: почему выбранное условие необходимо; отдельно `OPEN` части.
3. Product chain: key resolution, callbacks, casts, guard и relevant sites.
4. Coverage: просмотренные пути, alternatives, незакрытые обязательства.
5. Controls: команды, результаты и предел того, что доказывают тесты.
6. Comparison: govulncheck baseline, deterministic verdict, LLM proposals
   и verdict, вызовы и стабильность; необходимость проверки test-only scope.
7. Conclusion: следующий шаг с явным основанием.

- [ ] Использовать сравнительную таблицу, не смешивая исследовательские
  статусы с domain enums:

| Product | Research status | Govulncheck | Det verdict | LLM proposal/verdict | Open obligations |
|---|---|---|---|---|---|
| bytes | Проверить `BLOCKED_BY_TYPE_GATE` | Фактический baseline | Фактический verdict | Фактический результат | Перечислить |
| string | `PRECONDITION_NOT_EXCLUDED` | Фактический baseline | Фактический verdict | Фактический результат | Перечислить |
| callback | `PRECONDITION_NOT_EXCLUDED` | Фактический baseline | Фактический verdict | Фактический результат | Перечислить |
| dynamic | `CONFIG_DEPENDENT` | Фактический baseline | Фактический verdict | Фактический результат | Перечислить |

- [ ] Выбрать ровно один исследовательский итог:
  - **Перспективно для checker:** necessity обоснована, relevant paths
    замкнуты, controls различены; перечислить facts для следующего checker.
  - **Полезно для эксперта:** существенный proof obligation открыт;
    автоматическое снятие не обосновано.
  - **Гипотеза опровергнута:** назвать конкретный path/неверное допущение.
- [ ] Отдельно оценить LLM discovery. Если основание нашёл только человек
  при audit, не приписывать его LLM. Если govulncheck молчит, не заявлять
  дополнительное снятие относительно baseline.
- [ ] Добавить замечание о type mismatch и статусе пересмотра в
  `real-jose-decrypt.md`. Не переписывать молча прежнюю truth и не менять
  `expect` canonical real corpus в этом исследовательском change.
- [ ] В `eval/README.md` добавить research command, фактический результат
  и ограничения. Не пересчитывать прежний `3/23` по informational cases.
- [ ] Не копировать raw reports с приватными absolute paths в tracked
  документы; использовать relative source paths и `${RESEARCH_ROOT}`.
- [ ] Запустить проверку новых файлов и root suite:

```bash
gofmt -w eval/products/research-jose-{bytes,string,callback,dynamic}/*.go
go vet ./...
go test ./...
git diff --check
git status --short
```

- [ ] Отдельно подтвердить generated-module tests из шага 3.4: root suite
  не покрывает эти product directories из-за module boundary.
- [ ] Если changes вне разрешённого scope нужны для продолжения,
  остановиться и записать requirement next slice. Не менять analyzer;
  его будущий change требует отдельного дизайна, полного live corpus
  и `false-safe=0`.
- [ ] После готового досье и проверки артефактов закрыть исследовательский
  backlog-пункт. Если обоснован checker, добавить отдельный backlog item
  с требованиями; не реализовывать его в этой задаче.

**Completion report:** назвать созданные артефакты, что выполнено/не
выполнено, исследовательский итог, открытые обязательства, реальные
команды проверок и ограничения. Не утверждать automatic dismissal без
соответствующего persisted machine proof.
