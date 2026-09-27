# DATABASE / INTERNAL_SERVICE data origins — план фичи (gap-analysis кандидат #5)

Статус: done. Закрывает первый слой «Data origins» в `09-gap-analysis.md`:
оба origin'а из enum спеки §15 больше не «всегда UNKNOWN».

## Проблема

`OriginDatabase`/`OriginInternalService` существовали в enum и уже
учитывались evaluator'ом как deploy-dependent, но provenance-анализ их
никогда не порождал: `rows.Scan(&x)`-populate, gRPC-стабы, http-клиенты
на конфигурируемых endpoint'ах — всё падало в UNKNOWN или хуже.

## Что сделано

- **`populateOrigin`** (`goanalysis/provenance.go`): out-parameter writes
  `f(..., &v)` — ищется вызов, пишущий в `&v`. DB-ресиверы (`sql.Rows`,
  `pgx`, `gorm`, `mongo`, `redis`, `etcd`, `gocql`, `elasticsearch`,
  `sqlx`) → `DATABASE`; gRPC-стабы (ресивер в пакете, импортирующем
  `google.golang.org/grpc`) → `INTERNAL_SERVICE`; unmarshal/decode-семья
  пропагатирует origin источника (для методов — receiver, для функций —
  data-аргумент).
- **`isDBFunc`** — результат `database/sql`/driver-вызовов тоже `DATABASE`
  (`db.Query(...)` присвоение).
- **`httpClientOrigin`** — `http.Get/Post/Head/PostForm` + `*http.Client.*`:
  endpoint-аргумент, резолвящийся в CONFIGURATION/DATABASE →
  `INTERNAL_SERVICE` (сервисная граница — deployment property);
  литеральный/внешний URL → `EXTERNAL_UNTRUSTED` (прежняя семантика).
- **Passthrough** — `io.ReadAll`, `bufio.NewScanner`, `NewDecoder`,
  `NewRequest(url-arg)`, `url.Parse` + акцессоры `Text()/Bytes()/String()`
  пропагатируют origin входа — иначе цепочка рвалась на обёртке.
- **Фикс**: `classifySelector` терял `enc` — `resp.Body` не резолвился в
  локальное присваивание; теперь прозрачный селектор сохраняет контекст.

## Семантика

Evaluator уже трактует DATABASE/INTERNAL_SERVICE как deploy-dependent →
UNKNOWN → INCONCLUSIVE. Это осознанно: «атакующий контролирует запись в
БД/ответ сервиса» — вопрос границы доверия, не кода. Никакого FALSE или
TRUE на этих origins по умолчанию — небезопасно в обе стороны.

## Покрытие

- e2e: `testdata/dbprod` (`rows.Scan(&s)` → Parse), `testdata/svcprod`
  (`http.Get(os.Getenv("SVC_URL"))` → ReadAll → Parse) — оба дают
  DATAFLOW с правильным origin и INCONCLUSIVE.
- eval corpus: `db-populated-input`, `svc-config-endpoint`.
- Фикстуры — только `database/sql` (stdlib): driver-пакеты детектятся по
  пути, живой проверки на реальном gRPC/redis нет.

## Границы

- Детекция по пакетному пути (`strings.Contains(pkgPath,...)`) — эвристика;
  кастомные обёртки/ORM вне списка не распознаются.
- `EXTERNAL_AUTHENTICATED` различён для outbound HTTP (позже):
  `hasAuthMarkers` ищет credential-маркеры в enclosing-функции —
  `Authorization`-литерал, `SetBasicAuth`, oauth/credentials-хелперы →
  `client.Do` через аутентифицированный клиент = `EXTERNAL_AUTHENTICATED`.
  Claim-семантика не меняется (authenticated peer всё ещё
  attacker-capable); различие — provenance-честность. Inbound auth
  (middleware за пределами фрейма) не определяется. `GENERATED` частично.
- `Scan` через указатель на структуру (`rows.Scan(&x.Field)`) — покрыто
  только для `&ident`, KeyValue/Index-адресаты не ищутся.
- Запись в БД самим продуктом (taint «product wrote it earlier») не
  моделируется — DATABASE остаётся deploy-dependent.
