# Deployment/Exposure facts — план фичи (gap-analysis кандидат #2)

Статус: done. Приоритет #2 из [`gap-analysis.md`](../../gap-analysis.md).

## Проблема

Каждый peer-input TRUE и EXPLOITABLE-вердикт несёт caveat «peer
identity/exposure — deployment property». Спека (§12) требует учитывать
deployment configuration как факт. Сейчас между «уязвимый путь
эксплуатируем» и «атакующий реально может до него достучаться» стоит
рукотворная оговорка, которую можно заменить детерминистичными фактами.

## Решение

Собирать **exposure facts** как evidence третьего класса (после call
paths и module usage): сетевая экспозиция уязвимой поверхности.

```text
inbound:  net.Listen / http.Server.Addr / grpc Serve / tls.Listen
          → bind-адрес + классификация scope
outbound: dial-подобные вызовы в уязвимый модуль
          → endpoint + источник значения
configs:  репо-скан *.yaml|env|toml|json|ini|conf по address-ключам
          → разрешение env/ident-источников
```

### Дизайн-решения

- **Supporting + claim, не mandatory.** Exposure не гейтит вердикт:
  unresolved-конфиг не должен порождать ложный safe/unsafe. TRUE-claim
  на `C-EXPOSURE` (supporting condition) перечисляет факты; scope
  («loopback-only bind», «endpoint operator-configured») идёт в
  explanation/limitations.
- **Факт ≠ вердикт.** `0.0.0.0:9090` — факт; «интернет-экспонирован» —
  интерпретация фиксируется scope'ом, но окончательный peer-trust —
  ответственность вердикта человека. Мы заменяем caveat «deployment
  property» на конкретное «listener binds :9090 all-interfaces per
  config.yaml:14 / endpoint from env AMQP_URL».
- **Outbound скопом по модулю.** Уязвимости client-side библиотек
  (amqp/redis/grpc-client) экспонируются через то, *куда* продукт
  соединяется — dial-сайты фильтруются по vuln-модулю, аргумент
  резолвится: literal → значение; const/var → инициализатор;
  `os.Getenv` → env-ключ → поиск в конфиг-скане.
- **Общий scope-классификатор:** `all-interfaces` (`:port`, `0.0.0.0`,
  `[::]`), `loopback` (`127.0.0.1`, `::1`, `localhost`), `unix`,
  `host-specific`, `unknown`. Для outbound: `static-endpoint` |
  `configured` | `unknown`.

## Компоненты

| Файл | Что |
|---|---|
| `domain.go` | `ExposureFact{Direction,Kind,Address,AddressSource,Scope,CallSite}`; `EvidenceGraph.Exposures` + `AddExposure`; `CheckExposure` param value |
| `internal/exposure/scan.go` (new pkg) | `ScanRepo(root)`: walk конфиг-файлов → `{Key,Value,File,Line}` по `(listen|bind|addr|host|port|dsn|url|endpoint)-ish` ключам; `ScopeOf(addr)` классификатор |
| `goanalysis/source.go` | `ListenSites(ctx)` — как FindListeners + извлечение addr-аргумента (`exprValue`: literal/const/var/`os.Getenv`/selector); `DialSites(ctx, module)` — call sites `Dial*\|Connect\|Open\|NewClient` в модуль + addr-аргумент |
| `states.go` | `runExposure` в CollectEvidence: facts → `Exposures` + evidence-записи; резолв `env:`/`config:`-источников через config-scan |
| `evaluator/exposure.go` | `Exposure` evaluator: `check=exposure` → TRUE (факты перечислены, scope в explanation) / UNKNOWN (фактов нет) |
| `patterns.go` | `C-EXPOSURE` supporting-шаблон в peer-driven и NIL_DEREF паттернах (`Kind:CONFIGURATION, params{check:exposure}`) |
| `main.go` | `evaluator.Exposure{}` в цепочку до `VersionFact` |

## Ожидаемый результат на живых кейсах

- 4× EXPLOITABLE RabbitMQ: `C-EXPOSURE` перечисляет dial-сайты в
  `amqp091-go` + endpoint-источник (`env:`/`config:`/literal) — caveat
  «deployment property» заменяется фактом.
- gRPC: bind-адрес(а) `grpc.Server.Serve` listener'ов — loopback vs
  all-interfaces виден в отчёте.

## Тесты

- scope-классификатор: таблица адресов → scope;
- `exprValue`/`ListenSites`: literal, const, `os.Getenv`, config-field —
  фикстура `testdata/listenprod`;
- `DialSites`: фикстура с dial-вызовом в dep-модуль;
- e2e: peer-driven advisory → supporting claim C-EXPOSURE с фактами;
- регрессия: отчёт, suite, race.

## Не входит

- Auth-middleware анализ (отдельный кандидат);
- mandatory-гейтинг вердикта экспозицией;
- k8s/docker-compose манифесты (воля при необходимости — config-scan
  легко расширяется);
- соотнесение listener↔vuln по пакету (v1 считает глобально).
