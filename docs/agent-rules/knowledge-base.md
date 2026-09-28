# Knowledge base: правила правки `internal/goanalysis/knowledge.json`

Читать перед изменением базы знаний экосистемы или схемы `--knowledge`.

## Где что живёт

- `internal/goanalysis/knowledge.json` — единственный источник
  встроенных дефолтов (embedded в бинарь). **Не дублировать записи в
  Go-коде** — литеральных таблиц в `*.go` быть не должно.
- `internal/goanalysis/knowledge.go` — типы, валидация, мерж, digest.
- Схема файла = `KnowledgeFile`; эффективная база = `Knowledge` +
  `Index.KB` (nil → дефолты).

## Обязательно при изменении записей

- **Бампай `data_version` датой** (`"data_version": "YYYY-MM-DD"`) —
  по `sources` в отчётах видно, на какой ревизии данных считался
  вердикт. Без бампа отчёт соврёт про использованную базу.
- `digest` пересчитывается сам по содержимому — вручную не трогать.
- Записи — только универсальная семантика экосистемных API; правило
  допустимого содержимого — `generality.md`.

## Версии и метаданные файла

- `schema_version` — уровень ФОРМАТА, не данных. Бампится только при
  смене структуры файла (например, per-language секции); параллельно
  подними `KnowledgeSchemaVersion` в коде. Файл свежей схемы старым
  бинарём должен честно отклоняться ошибкой версии — не ломай peek
  до strict-decode.
- `language: "go"` — семейство анализатора; встроенный файл всегда go.
- `name`/`labels` — provenance-метки, информационные; встроенная база
  — `builtin`/`upstream`.

## Инварианты расширения

- Мерж только аддитивный: новый ключ — ок; повтор с тем же значением —
  no-op; переопределение значения — ошибка. Тихой перезаписи быть не
  может: неверная запись опаснее пропущенной (пропуск → UNKNOWN).
- Валидация при загрузке обязана ловить: unknown key, невалидный
  `DataOrigin`, отрицательные индексы, `false` в set-полях,
  неполный `listener_primitives`, чужой `language`, будущую
  `schema_version`.
- Нет автообнаружения файлов в репозитории продукта — только явный
  `--knowledge` (план: `dev/plans/knowledge-base-plan.md`).

## Проверка

- `go test ./internal/goanalysis/ -run Knowledge` — обязательные
  тесты: `TestDefaultKnowledgeEmbedded` (embedded парсится, дамп
  round-trip), `TestKnowledgeExtendSourceFuncs` (расширение меняет
  origin на `testdata/kbprod`), валидация/конфликты/provenance.
- `vuln-analyzer knowledge` — посмотреть эффективную базу;
  `--knowledge <file>` на сабкоманде — проверить файл до прогона.
