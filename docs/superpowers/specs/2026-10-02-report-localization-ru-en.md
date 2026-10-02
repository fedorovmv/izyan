# Design: Report Localization (RU & EN Dual Generation)

- **Date:** 2026-10-02
- **Topic:** Full Russian localization of `report.md`, generation of dual `report.en.md`, and CLI `--lang` flag support
- **Status:** Proposed

---

## 1. Context & Motivation

The redesigned `report.md` establishes an Inverted Pyramid layout. However, the report text was still predominantly in English (e.g. `Vulnerability analysis`, `Verdict`, `mandatory exploit condition is proven false`, `module present`, `package present`, `Root cause`, `Mandatory conditions`), creating cognitive friction for Russian-speaking developers and AppSec engineers.

Furthermore, user feedback requires:
1. Translating technical terms and checks into clear Russian phrasing (e.g. `module present` -> `Наличие модуля в зависимостях`, `package present` -> `Уязвимый пакет входит в сборку`).
2. Translating verdict reasons into clear Russian explanations (e.g. `mandatory exploit condition is proven false` -> `Обязательное условие эксплуатации опровергнуто (уязвимый путь исполнения отсутствует)`).
3. Renaming the rationale header strictly to `## Резюме`.
4. Generating both `report.md` (Russian primary) and `report.en.md` (English international) simultaneously during each analysis run.
5. Providing a CLI `--lang=ru|en` flag (defaulting to `ru`) to control console output and preferred report orientation.

---

## 2. Architecture & Behavior

### Report Generator Dual-Output (`internal/report`)
In `internal/report/report.go`:
- `Markdown(c *domain.AnalysisCase, lang string) string`:
  - If `lang == "en"`, renders English headings, English table column names, and English verdict reasons.
  - If `lang == "ru"` (default), renders fully translated Russian headings, human-readable Russian table checks, Russian condition descriptions, and localized verdict explanations.
- `Write(dir string, c *domain.AnalysisCase) error`:
  - Writes `report.json`
  - Writes `openvex.json`
  - Writes `cyclonedx.json`
  - Writes `report.md` (Russian rendered via `Markdown(c, "ru")`)
  - Writes `report.en.md` (English rendered via `Markdown(c, "en")`)

### CLI Language Flag (`cmd/analyzer`)
- New flag: `--lang` with values `ru` (default) and `en`.
- Used to format the CLI stdout summary and determine the primary report language if needed.

---

## 3. Localization Dictionaries

### Verdict Reasons
| English Internal String | Russian Localization |
|---|---|
| `mandatory exploit condition is proven false` | `Обязательное условие эксплуатации опровергнуто (уязвимый путь исполнения отсутствует)` |
| `all mandatory conditions met` | `Все обязательные условия эксплуатации выполнены (уязвимость подтверждена)` |
| `resolved version outside affected range` | `Разрешённая версия библиотеки находится вне уязвимого диапазона` |
| `no exploit conditions met` | `Ни одно условие эксплуатации не выполнено` |
| `locus packages absent from build graph` | `Уязвимый код физически не включён в сборку` |

### Affected Analysis Checks
| English Check | Russian Label |
|---|---|
| `module present` | `Наличие модуля в зависимостях` |
| `resolved version` | `Разрешённая версия в go.mod` |
| `version affected` | `Версия входит в диапазон уязвимых` |
| `package present` | `Уязвимый пакет входит в сборку` |
| `build relevant` | `Код компилируется для целевой платформы` |
| `modules probed` | `Проверенные модули` |
| `modules linked` | `Скомпилированные модули` |
| `modules version-unresolved` | `Модули с неопределённой версией` |
| `packages probed` | `Проверенные пакеты` |
| `evidence` | `Идентификаторы доказательств (Evidence IDs)` |

### Standard Exploit Conditions
| Condition ID | Russian Description |
|---|---|
| `C-REACH` | `Достижимость символов: хотя бы одна из уязвимых функций вызывается в коде продукта` |
| `C-PEER-INPUT` | `Контроль ввода: параметры уязвимой функции контролируются удалённым клиентом` |
| `C-CONSTRAINT` | `Нарушение ограничений: удалённый клиент может передать входные данные, вызывающие сбой` |
| `C-LOCUS` | `Выполнение уязвимого кода: пакеты дефектного кода входят в граф сборки приложения` |
| `C-EXPOSURE` | `Сетевая доступность: наличие открытых сетевых портов или исходящих подключений` |
| `C-TLS-VERIFY` | `Проверка TLS: отключение проверки сертификатов позволяет передавать трафик без доверенного канала` |

---

## 4. Section Structure Comparison (RU vs EN)

| Section | Russian (`report.md`) | English (`report.en.md`) |
|---|---|---|
| Header | `# Анализ уязвимости: <ID>` | `# Vulnerability analysis: <ID>` |
| Verdict | `## Вердикт: <VERDICT>` | `## Verdict: <VERDICT>` |
| Rationale | `## Резюме` | `## Executive Summary` |
| Remediation | `## Рекомендации по устранению` | `## Remediation` |
| Evidence | `## Доказательная база` | `## Evidence Dossier` |
| Affected | `### Применимость (Affected Analysis)` | `### Affected Analysis` |
| Claims | `### Статус условий эксплуатации (Claims)` | `### Claims Status` |
| Exposures | `### Точки входа (Exposure Facts)` | `### Exposure Facts` |
| Exploit/Locus | `### Модель эксплуатации и сайты дефекта` | `### Exploit Model & Defect Locus` |
| Collapsible Audit | `<details><summary><b>Технические детали и аудит...</b></summary>` | `<details><summary><b>Technical Details & Audit...</b></summary>` |

---

## 5. Backward Compatibility & Verification

- `report.json`, `openvex.json`, and `cyclonedx.json` remain in canonical English.
- Tests will verify both `Markdown(c, "ru")` and `Markdown(c, "en")` outputs.
- Existing tests expecting `Markdown(c)` default to `Markdown(c, "ru")` (or backward-compatible wrapper).
