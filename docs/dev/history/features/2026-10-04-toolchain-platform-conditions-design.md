# Design Specification: B18 — Snapshot/Toolchain-факты как Platform Conditions

**Дата:** 2026-10-04  
**Статус:** Draft (на ревью)  
**Бэклог:** B18 (P2, §2 `docs/dev/gap-analysis.md`)  
**Дефект:** D3 (P2, §3 `eval/ground-truth.md`)  
**Целевой кейс:** `GHSA-33mj-cw25-m34h` в `eval/live-corpus.json` на эталонном продукте (`${VA_PRODUCT_REPO}`)

---

## 1. Контекст и проблема

При анализе уязвимостей в зависимостях часто встречаются дефекты, эксплуатируемость которых зависит от среды выполнения или версии тулчейна Go.
Яркий пример — **`GHSA-33mj-cw25-m34h`** (уязвимость в `github.com/rabbitmq/amqp091-go`):
- Функция `tlsConfigFromURI` создаёт `*tls.Config` без явного задания `MinVersion`.
- В компиляторах Go < 1.18 рантайм `crypto/tls` допускал согласование устаревших протоколов TLS 1.0 и 1.1.
- Начиная с **Go 1.18**, стандартная библиотека Go по умолчанию форсит минимальную версию **TLS 1.2** (`tls.VersionTLS12`), делая downgrade-атаку невозможной на уровне платформы.

### Текущие дефекты в системе:
1. **Неверная классификация (дефект D3)**:
   Advisory содержит `CWE-316` («Cleartext Storage in Memory») наряду с `CWE-326` («Inadequate Encryption Strength»). Анализатор сопоставляет CWE-316 с `ClassInfoLeak` и создаёт нерелевантные условия (`C-DATA-PRESENT`, `C-EXPOSED`), завершая анализ вердиктом `INCONCLUSIVE`.
2. **Отсутствие связи с версией компилятора**:
   В модели эксплойта отсутствует класс криптографического/протокольного даунгрейда (`ClassCryptoDowngrade`) с обязательным платформенным условием `C-PLATFORM` (`PLATFORM_CONDITION`).
3. **Источники информации о версии компилятора**:
   `go.mod` указывает лишь минимальный синтаксис языка, а не реальный компилятор, собравший релиз. Реальная версия Go поступает либо из бинарника (`--binary`), либо из метаданных тикета задачи (включая извлечение через LLM-интейк), либо из аргументов CI/CD пайплайна (`--release-go-version`), либо из локального `go version`.

Истинный вердикт для современных релизов продукта — **`NO_EXPLOIT_PATH_FOUND`** с доказанным фальсификатором `FalsifierSnapshotFactMismatch` на обязательном условии платформы.

---

## 2. Архитектурное решение

```
┌────────────────────────────────────────────────────────┐
│  Входные данные:                                       │
│  - Бинарник (--binary)            -> ReleaseGoVersion  │
│  - Тикет (--ticket / LLM intake)  -> ReleaseGoVersion  │
│  - CI флаг (--release-go-version) -> ReleaseGoVersion  │
│  - Локальный компилятор (go version) -> GoVersion      │
└───────────────────────────┬────────────────────────────┘
                            │ ProductSnapshot
                            ▼
┌────────────────────────────────────────────────────────┐
│  Классификация уязвимости (Classify):                 │
│  - CWE-326, 327, 757 -> ClassCryptoDowngrade           │
│  - TLS MinVersion / Downgrade keywords                 │
└───────────────────────────┬────────────────────────────┘
                            │ Class
                            ▼
┌────────────────────────────────────────────────────────┐
│  Модель эксплойта (Exploit Pattern):                   │
│  - C-REACH: вызов уязвимого API                        │
│  - C-PLATFORM: go_version < 1.18 (Mandatory)           │
└───────────────────────────┬────────────────────────────┘
                            │ Condition
                            ▼
┌────────────────────────────────────────────────────────┐
│  Оценка и верификация (evaluator.Platform & NV):       │
│  - productGoVersion (v1.26.1) нарушает bound (<1.18)   │
│  - Claim: FALSE (FalsifierSnapshotFactMismatch)        │
│  - Negative Verification: VERIFIED                     │
│  - Итоговый вердикт: NO_EXPLOIT_PATH_FOUND            │
└────────────────────────────────────────────────────────┘
```

### 2.1. Извлечение версии Go из тикета (включая LLM-интейк)
1. В структуре `tracker.Ticket` (`internal/tracker/intake.go`) добавляются поля `GoVersion` и `Toolchain`.
2. В детерминистическом парсере тикетов (`intake.go`) поля `Go version:`, `Toolchain:`, `Compiler:` заполняют `Ticket.GoVersion`.
3. В LLM-интейке (`internal/tracker/llm_intake.go`):
   - Промпт `ticketExtractorSystemPrompt` инструктирует LLM извлекать `go_version` (например, `"go1.22.4"`, `"1.21"`).
   - В структуру `llmTicketExtraction` добавляется `GoVersion string json:"go_version"`.
   - Проводится детерминированная валидация (проверка формата и наличия подстроки в исходном тексте для защиты от галлюцинаций).
4. В `cmd/izyan/main.go` функция `applyTicket` передаёт `t.GoVersion` в `o.releaseGo` (если флаг не был задан явно).

### 2.2. Классификация уязвимостей (`internal/exploit/classify.go`)
1. Добавляется класс уязвимости:
   ```go
   ClassCryptoDowngrade Class = "CRYPTO_DOWNGRADE"
   ```
2. В `cweClass` регистрируются:
   - `"326": ClassCryptoDowngrade` (Inadequate Encryption Strength)
   - `"327": ClassCryptoDowngrade` (Use of a Broken or Risky Cryptographic Algorithm)
   - `"757": ClassCryptoDowngrade` (Selection of Less-Secure Algorithm During Negotiation)
3. В `keywordClass` добавляется правило:
   ```go
   {regexp.MustCompile(`(?i)(tls|ssl).*min(imum)?[- ]?version|downgrade.*(tls|ssl|protocol|cipher)|implicit.*toolchain.*(tls|ssl)|minversion.*(toolchain|default)`), ClassCryptoDowngrade}
   ```
   Позиционируется перед `ClassInfoLeak`, чтобы упоминания «cleartext on wire» в контексте TLS не приводили к ложному `INFO_LEAK`.

### 2.3. Паттерн эксплойта и граница версии (`internal/exploit/patterns.go`, `builder.go`)
1. В `Registry` добавляется паттерн для `ClassCryptoDowngrade`:
   - `Mandatory`:
     - `C-REACH` (`ConditionSymbolReachable`): достижимость затронутых символов (`AffectedSymbols`).
     - `C-PLATFORM` (`ConditionPlatform`): компилятор допускает слабый криптографический протокол:
       `Params: map[string]string{"go_version": bound}`.
   - `Supporting`:
     - `C-EXPOSURE` (`ConditionConfiguration`): проверка сетевой экспозиции.
2. Извлечение границы версии (`builder.go`):
   - Сканирование `Summary` и `Description` регулярным выражением:
     `(?i)(?:Go|toolchain)[^\w\n]*(?:<|<=|prior to|before)\s*v?(\d+\.\d+(?:\.\d+)?)`
   - Для `GHSA-33mj` извлекается `"<1.18"`.
   - Если явная граница не найдена, но класс `ClassCryptoDowngrade` касается TLS MinVersion в Go, используется дефолтный платформенный пол `"<1.18"`.

### 2.4. Вычисление вердикта и негативная верификация
1. Оценщик `evaluator.Platform` (`internal/evaluator/platform.go`) получает `C-PLATFORM`:
   - Извлекает версию компилятора продукта `productGoVersion(c.Product)`.
   - Проверяет границу: для `productGoVersion = "v1.26.1"` условие `<1.18` нарушается.
   - Формирует результат: `ClaimFalse`, фальсификатор `FalsifierSnapshotFactMismatch`, пояснение: `"snapshot fact mismatch: go_version: want <1.18, product is v1.26.1"`.
2. В `internal/goanalysis/negative.go` функция `verifySnapshotFalse` подтверждает фальсификатор по фактам компилятора (`Status: VERIFIED`).
3. Так как опровергнуто обязательное условие (`Mandatory`), выносится аудируемый вердикт **`NO_EXPLOIT_PATH_FOUND`** (0 fail, 0 false-safe).

---

## 3. План тестирования и критерии приёмки

1. **Юнит-тесты**:
   - `internal/tracker/llm_intake_test.go`: проверка извлечения `go_version` из произвольного текста тикета.
   - `internal/tracker/intake_test.go`: проверка детерминированного парсинга полей `Go version:` и `Toolchain:`.
   - `internal/exploit/classify_test.go`: проверка корректной классификации `GHSA-33mj` в `ClassCryptoDowngrade` вместо `INFO_LEAK`.
   - `internal/exploit/patterns_test.go`: проверка синтеза `C-PLATFORM` с параметром `go_version: "<1.18"`.
   - `internal/evaluator/platform_test.go`: проверка вычисления `C-PLATFORM` на различных версиях Go (<1.18 → TRUE, >=1.18 → FALSE, отсутствие версии → UNKNOWN).
2. **Интеграционный тест на live-корпусе**:
   - Запуск `go run ./cmd/izyan eval --corpus eval/live-corpus.json --case ghsa-33mj-cw25-m34h`.
   - Ожидаемый вердикт: **`NO_EXPLOIT_PATH_FOUND`** (0 fail, 0 false-safe).
3. **Регрессионная безопасность**:
   - Автономный корпус `eval/corpus-real.json` (38 кейсов) должен сохранять 38/38 PASS, 0 FAIL, `false-safe = 0`.
   - `gofmt`, `go vet ./...`, `go test ./...` — чисто.
   - Нулевое присутствие корпоративных имен (`cloud-esb-micro`) и приватных путей.
