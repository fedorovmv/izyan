# Dynamic-маркеры и negative verification

Читать перед работой в `internal/goanalysis/negative.go` и
`internal/goanalysis/source.go` (ScanDynamic).

Import ≠ write. Маркеры различаются по степени:

- `reflect_write` — `reflect.Value.Set*`; ослабляет guard-FALSE только
  при exported покрытом поле (`hasExportedCoveredField`); bare
  `reflect` импорт для guards-claims игнорируется.
- `unsafe_write` — store через unsafe-derived deref/index
  (`*(*T)(unsafe.Pointer(&f)) = v`, `unsafe.Slice(...)[i] = v`);
  ослабляет безусловно (пишет и unexported).
- `unsafe_ptr` — материализация `unsafe.Pointer`/`unsafe.Add`;
  безусловно ослабляет (aliased-записи неотслеживаемы дешёво).
- `func_value`, `go:linkname`, interface dispatch, build-tag gated,
  plugin — консервативные CONTRADICTED/INSUFFICIENT_SCOPE по scoped
  правилам.

Верификационные статусы: VERIFIED (покрытие + нет маркеров),
CONTRADICTED (конкретный контрфакт), INSUFFICIENT_SCOPE (не покрыто).
UNKNOWN-origin при перетрейсе → INSUFFICIENT_SCOPE, не CONTRADICTED:
отсутствие доказательства ≠ контрадикция.
