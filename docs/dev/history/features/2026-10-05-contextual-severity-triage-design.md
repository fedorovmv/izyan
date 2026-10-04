# B33: Контекстная критичность и триаж CVE с номинальным CVSS 10.0

## 1. Контекст и проблема

Сканеры безопасности (NVD, OSV, GitHub Advisory, Dependabot) оперируют номинальными оценками CVSS (например, **CVSS 9.8–10.0 / Critical / Blocker**). 
В реальных проектах эти оценки вызывают массовую блокировку релизов («security gate failure») и перегружают команды триажа:
1. Уязвимость может быть объявлена в модуле, но код физически не скомпилирован в бинарный файл (`NOT_AFFECTED`).
2. Обязательные условия атаки (например, недостижимость функций, неподходящая версия компилятора или доверенный локальный источник) опровергнуты детерминированным анализом (`NO_EXPLOIT_PATH_FOUND`).
3. Код уязвим (`EXPLOITABLE`), но сервис слушает исключительно локальный сокет (`127.0.0.1`), защищён обязательной аутентификацией, либо представляет собой CLI-утилиту без сетевых слушателей. В этом случае номинальный риск 10.0 фактически является локальным риском уровня P2/Medium (SLA 30 дней), а не аварийным блокером P0 (SLA 24 часа).

**Цель фичи B33:** Реализовать детерминированный движок контекстной переоценки (Triage & Contextual Risk Engine), который сопоставляет номинальную критичность advisory с реальной архитектурой продукта и выдает:
- Точный контекстный уровень риска (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`) и скор (0.0–10.0).
- Приоритет в очереди устранения (`P0 Blocker`, `P1 Critical`, `P2 High/Medium`, `P3 Low`, `DISMISSED`).
- Рекомендуемый SLA на исправление (24 часа, 7 дней, 30 дней, либо снято).
- Аудируемое обоснование для ИБ и разработчиков (*«Почему номинальный CVSS 10.0 понижен или подтверждён»*).

---

## 2. Модель данных (`internal/domain/domain.go`)

```go
type RiskLevel string

const (
	RiskLevelCritical RiskLevel = "CRITICAL"
	RiskLevelHigh     RiskLevel = "HIGH"
	RiskLevelMedium   RiskLevel = "MEDIUM"
	RiskLevelLow      RiskLevel = "LOW"
	RiskLevelNone     RiskLevel = "NONE"
	RiskLevelUnknown  RiskLevel = "UNKNOWN"
)

type TriagePriority string

const (
	PriorityP0        TriagePriority = "P0"        // Blocker (SLA: 24h immediate)
	PriorityP1        TriagePriority = "P1"        // Critical (SLA: 7d)
	PriorityP2        TriagePriority = "P2"        // Medium / High (SLA: Sprint / 30d)
	PriorityP3        TriagePriority = "P3"        // Low / Minor (SLA: Backlog)
	PriorityDismissed TriagePriority = "DISMISSED" // No action / False alarm (SLA: None)
)

type ContextualRiskStatus string

const (
	RiskStatusAssessed      ContextualRiskStatus = "ASSESSED"
	RiskStatusProvisional   ContextualRiskStatus = "PROVISIONAL"
	RiskStatusNotApplicable ContextualRiskStatus = "NOT_APPLICABLE"
	RiskStatusUnassessed    ContextualRiskStatus = "UNASSESSED"
)

type ContextualRisk struct {
	Status           ContextualRiskStatus `json:"status"`
	BaseSeverity     string               `json:"base_severity,omitempty"`
	BaseScore        float64              `json:"base_score,omitempty"`
	ContextualLevel  RiskLevel            `json:"contextual_level"`
	ContextualScore  float64              `json:"contextual_score,omitempty"`
	Priority         TriagePriority       `json:"priority"`
	SLA              string               `json:"sla,omitempty"`
	AdjustmentReason string               `json:"adjustment_reason"`
	Factors          RiskFactors          `json:"factors"`
}

type RiskFactors struct {
	Verdict        string `json:"verdict"`
	Exposure       string `json:"exposure"`       // PUBLIC (0.0.0.0), INTERNAL (127.0.0.1), NONE (no listeners)
	Authentication string `json:"authentication"` // REQUIRED, NONE, UNKNOWN
	PayloadControl string `json:"payload_control"`// UNTRUSTED_EXTERNAL, CONSTANT, TRUSTED_INFRASTRUCTURE
	BlastRadius    string `json:"blast_radius"`   // PROCESS_CRASH_DOS, DATA_LEAK, RCE, DOWNGRADE, UNKNOWN
}
```

---

## 3. Источники номинальной критичности (Base Severity Ingestion)

1. **OSV/GHSA JSON (`internal/vulnerability/osv.go`):**
   - Парсинг массива `severity`:
     - Поддержка `CVSS_V3` и `CVSS_V4`.
     - Извлечение числового скора (например, `CVSS:3.1/AV:N/AC:L/...` $\rightarrow$ парсинг вектора или прямое чтение базы).
   - Парсинг `database_specific.severity`:
     - Строковые константы `CRITICAL`, `HIGH`, `MODERATE`, `MEDIUM`, `LOW`.
2. **Тикет (`internal/tracker/intake.go`):**
   - Чтение полей `severity: "BLOCKER" / "CRITICAL"` и `cvss: "10.0"`.
3. **Безопасная нормализация:**
   - Если указан скор $\ge 9.0$ либо строка `CRITICAL` / `BLOCKER` $\rightarrow$ BaseLevel = `CRITICAL`, BaseScore = `score` (или 9.8 по умолчанию).
   - Если скор $7.0..8.9$ либо строка `HIGH` $\rightarrow$ BaseLevel = `HIGH`, BaseScore = 7.5.
   - Если скор $4.0..6.9$ либо строка `MEDIUM` / `MODERATE` $\rightarrow$ BaseLevel = `MEDIUM`, BaseScore = 5.0.
   - Если скор $< 4.0$ либо строка `LOW` $\rightarrow$ BaseLevel = `LOW`, BaseScore = 3.0.

---

## 4. Матрица триажа и алгоритм переоценки (`internal/risk`)

Функция `Assess(v domain.Vulnerability, c *domain.AnalysisCase, verdict domain.VerdictResult) domain.ContextualRisk`:

### Правило 1: Снятие риска (Dismissed / NOT_APPLICABLE)
* **Условие:** `verdict.Verdict == VerdictNotAffected` ИЛИ `verdict.Verdict == VerdictNoExploitPath`.
* **Результат:**
  * `ContextualLevel = RiskLevelNone`
  * `ContextualScore = 0.0`
  * `Priority = PriorityDismissed`
  * `SLA = "None (No remediation required)"`
  * `Status = RiskStatusNotApplicable` (для NotAffected) или `RiskStatusAssessed` (для NoExploitPath).
  * `AdjustmentReason`:
    * Для `NOT_AFFECTED`: *«Уязвимый модуль не слинкован в бинарный граф сборки продукта (`go list -deps`). Эксплуатация физически невозможна. Блокировка сборки снята.»*
    * Для `NO_EXPLOIT_PATH_FOUND`: *«Обязательное условие эксплуатации опровергнуто детерминированной верификацией. Уязвимый путь вызова отсутствует. Блокировка сборки снята.»*

### Правило 2: Подтверждённый Blocker (P0)
* **Условие:** `verdict.Verdict == VerdictExploitable` И `Exposure == PUBLIC` (`0.0.0.0` или публичный сетевой слушатель) И `Authentication != REQUIRED`.
* **Результат:**
  * `ContextualLevel = RiskLevelCritical`
  * `ContextualScore = max(BaseScore, 9.5)`
  * `Priority = PriorityP0`
  * `SLA = "24h (Immediate remediation required)"`
  * `Status = RiskStatusAssessed`
  * `AdjustmentReason`: *«Критическая уязвимость подтверждена: сервис слушает внешний сетевой интерфейс (0.0.0.0) без обязательной аутентификации.»*

### Правило 3: Понижение до High (P1)
* **Условие 3a:** `verdict.Verdict == VerdictExploitable` И `Exposure == PUBLIC`, НО `Authentication == REQUIRED`.
* **Условие 3b:** `verdict.Verdict == VerdictExploitable` И `Exposure == INTERNAL` (`127.0.0.1` / localhost), но последствия — RCE / Code Execution.
* **Результат:**
  * `ContextualLevel = RiskLevelHigh`
  * `ContextualScore = 7.5`
  * `Priority = PriorityP1`
  * `SLA = "7 days"`
  * `Status = RiskStatusAssessed`
  * `AdjustmentReason`: *«Уязвимость достижима извне, но защищена предварительной аутентификацией/шлюзом (эксплуатация требует валидных учетных данных).»*

### Правило 4: Понижение до Medium (P2)
* **Условие:** `verdict.Verdict == VerdictExploitable` И (`Exposure == INTERNAL` ИЛИ `Exposure == NONE`).
* **Результат:**
  * `ContextualLevel = RiskLevelMedium`
  * `ContextualScore = 4.5`
  * `Priority = PriorityP2`
  * `SLA = "Sprint (30 days)"`
  * `Status = RiskStatusAssessed`
  * `AdjustmentReason`: *«Сетевой доступ из внешней сети отсутствует (слушатель привязан к локальному интерфейсу 127.0.0.1 либо сетевые слушатели отсутствуют). Уязвимость переведена в плановый спринт.»*

### Правило 5: Неопределённость (INCONCLUSIVE)
* **Условие:** `verdict.Verdict == VerdictInconclusive`.
* **Результат:**
  * `Status = RiskStatusProvisional`
  * Для базовой критичности `CRITICAL` / `BLOCKER` $\rightarrow$ `Priority = PriorityP1` (Triage), `SLA = "7 days (Manual triage)"`.
  * Для базовой критичности `HIGH` / `MEDIUM` $\rightarrow$ `Priority = PriorityP2`.
  * `AdjustmentReason`: *«Условия эксплуатации не подтверждены и не опровергнуты; требуется ручной аудит входных данных.»*

---

## 5. Интеграция в отчётность и CLI

### 5.1. Текстовый отчёт `report.md`
Сразу после блока `## Вердикт` выводится блок:

```markdown
## Контекстная критичность и триаж (Triage Assessment)

| Параметр | Исходная оценка (CVE / NVD) | Контекстная оценка в продукте |
|---|---|---|
| **Критичность** | 🔴 **CRITICAL** (CVSS 10.0) | 🟡 **MEDIUM** (Score 4.5) |
| **Приоритет в очереди** | **P0 (Blocker)** | **P2 (Плановый спринт)** |
| **Рекомендуемый SLA** | 24 часа | 30 дней (Sprint) |
| **Статус оценки** | Номинальный | **ASSESSED** (Подтверждено контекстом) |

> ℹ️ **Обоснование переоценки:**
> Номинальная критичность CVSS 10.0 понижена до **P2 (Medium)**, так как сервис привязан исключительно к локальному интерфейсу (`127.0.0.1:8080`) и недоступен из внешней сети. Эксплуатация требует предварительной компрометации хоста.
```

### 5.2. JSON-отчёт `report.json`
В корневой объект `report.json` добавляется поле:
```json
"contextual_risk": {
  "status": "ASSESSED",
  "base_severity": "CRITICAL",
  "base_score": 10.0,
  "contextual_level": "MEDIUM",
  "contextual_score": 4.5,
  "priority": "P2",
  "sla": "Sprint (30 days)",
  "adjustment_reason": "Сетевой доступ из внешней сети отсутствует...",
  "factors": {
    "verdict": "EXPLOITABLE",
    "exposure": "INTERNAL",
    "authentication": "NONE",
    "payload_control": "UNTRUSTED_EXTERNAL",
    "blast_radius": "PROCESS_CRASH_DOS"
  }
}
```

### 5.3. Вывод CLI (`analyze` и `eval`)
В строке сводки печатается приоритет и дельта:
```bash
[1/1] CVE-2026-77412   EXPLOITABLE   priority: P2 (Medium, SLA: 30d)  [CVSS 10.0 -> 4.5: internal listener only]
```

---

## 6. План тестирования и критерии приёмки

1. **Юнит-тесты парсинга (`internal/vulnerability` и `internal/tracker`):**
   - Парсинг CVSS 3.1 / 4.0 векторов и числовых скоров.
   - Извлечение severity из билетов трекера.
2. **Юнит-тесты логики триажа (`internal/risk`):**
   - Тест 1: Номинальный 10.0 + `NOT_AFFECTED` $\rightarrow$ `DISMISSED`, `NONE (0.0)`, снятие блокировки.
   - Тест 2: Номинальный 10.0 + `NO_EXPLOIT_PATH_FOUND` $\rightarrow$ `DISMISSED`, `NONE (0.0)`.
   - Тест 3: Номинальный 10.0 + `EXPLOITABLE` + Public unauth $\rightarrow$ `P0 Blocker`, `CRITICAL (10.0)`.
   - Тест 4: Номинальный 10.0 + `EXPLOITABLE` + Internal loopback (`127.0.0.1`) $\rightarrow$ `P2`, `MEDIUM (4.5)`.
   - Тест 5: Номинальный 10.0 + `EXPLOITABLE` + Public with auth $\rightarrow$ `P1`, `HIGH (7.5)`.
   - Тест 6: Номинальный 10.0 + `INCONCLUSIVE` $\rightarrow$ `P1 Provisional (7.5)`.
3. **Регрессионные инварианты:**
   - Автономный корпус `eval/corpus-real.json` (38 кейсов) и живой корпус: `false-safe = 0`.
