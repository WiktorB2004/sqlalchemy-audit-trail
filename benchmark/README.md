# Benchmark

What does auditing cost? This benchmark measures two things on PostgreSQL:

- **Write overhead**: the same insert or update, and the same request with a
  `log()` call, with and without the library, and with both `on_error`
  settings.
- **Read latency** on a synthetic log of 5 million entries over 12 months:
  `list_groups`, `object_history` and `access_summary`, and how many
  partitions each one actually reads.

It is **not** a comparison with other libraries (sqlalchemy-continuum,
triggers, pgaudit), and it is not a tuned setup. It uses one connection and
one machine, with PostgreSQL in a local Docker container on stock settings.

## Headline

Measured 2026-09-26 on a laptop (PostgreSQL 18.6 in Docker, stock settings;
details below):

- **Writes:** auditing a flush of 1 object adds **2.4 ms** at p50 (a plain
  insert takes 3.4 ms; audited, 5.8 ms). With `on_error="raise"`, which
  skips the savepoint, it adds **1.5 ms**. A flush of 100 objects adds
  **11.4 ms**, about **114 µs per object** (9.8 ms with `"raise"`). A
  durable `log()` adds **6.7 ms**.
- **Installed but switched off** (`audit_enabled=False`) stays within
  0.6 ms of plain at p50.
- **Reads on 5M entries:** the first page of `list_groups` (50 groups) takes
  **18.5 ms** at p50 without a query window and **15.1 ms** with a 30-day
  window. PostgreSQL spends under 1 ms executing the queries of either. The
  window saves planning time: its plans hold 27 partition scans instead of
  82.
- Pagination reads **5 of 80 partitions** for a next page, including one
  six months back. Filters with no time bound (`actor_id`, `object_history`,
  `access_summary` over the whole history) read all 64 activity
  partitions, and come in at 10 to 22 ms here.

## Results

Raw JSON: `benchmark/results/run_20260926T104637Z_7e088fba.json`
(gitignored). Every number in this README comes from that run. The full run
took 677 s, including 302 s of seeding and 127 s of `VACUUM ANALYZE`.

### Environment

| | |
| --- | --- |
| CPU | Intel Core i7-8850H @ 2.60GHz, 12 threads |
| RAM | 15.5 GB visible to the WSL2 VM |
| OS | Linux 6.18 (WSL2 on Windows), Docker Engine 29.8.1 |
| PostgreSQL | 18.6 (`postgres:18` image via testcontainers), **stock config**: `shared_buffers` 128 MB, `work_mem` 4 MB, `jit` on, `synchronous_commit` on, `fsync` on |
| Client | Python 3.12.11, SQLAlchemy 2.1.0, psycopg 3.3.6 (sync `Session`) |
| Library | sqlalchemy-audit-trail 0.1.0 at commit 953974f |
| Round trip | `SELECT 1` on an open connection: p50 0.32 ms, p95 0.48 ms |

### Writes

Milliseconds per transaction, from `add_all`/change through `commit()`. There
were 1000 iterations for 1 and 10 objects and 300 for 100 objects, after 100
warm-up iterations per variant.
- `audited` uses the default `on_error="log"`; `"raise"` is the same
  capture without the savepoint.
- "Statements" counts what goes through the cursor per transaction, for
  plain / log / raise. BEGIN and COMMIT are not included.

| Operation | Objects | plain p50 / p95 | disabled p50 / p95 | audited p50 / p95 | audited, `"raise"` p50 / p95 | Added p50, `"log"` | Added p50, `"raise"` | Per object, log / raise | Statements |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| insert | 1 | 3.37 / 5.17 | 3.34 / 4.98 | 5.80 / 8.51 | 4.88 / 7.33 | +2.43 ms (+72%) | +1.52 ms (+45%) | 2429 / 1516 µs | 1 / 5 / 3 |
| insert | 10 | 3.98 / 6.69 | 4.05 / 6.59 | 7.68 / 11.86 | 6.34 / 9.63 | +3.70 ms (+93%) | +2.36 ms (+59%) | 370 / 236 µs | 1 / 5 / 3 |
| insert | 100 | 8.04 / 12.80 | 7.84 / 10.91 | 19.42 / 36.04 | 17.87 / 27.18 | +11.38 ms (+141%) | +9.83 ms (+122%) | 114 / 98 µs | 1 / 5 / 3 |
| update | 1 | 2.83 / 3.71 | 2.84 / 4.20 | 5.26 / 7.24 | 4.46 / 6.15 | +2.43 ms (+86%) | +1.63 ms (+58%) | 2427 / 1633 µs | 1 / 5 / 3 |
| update | 10 | 3.37 / 4.42 | 3.51 / 5.28 | 7.13 / 10.53 | 6.04 / 8.89 | +3.76 ms (+112%) | +2.68 ms (+80%) | 376 / 268 µs | 1 / 5 / 3 |
| update | 100 | 7.07 / 9.96 | 7.64 / 15.78 | 18.75 / 34.57 | 17.34 / 22.91 | +11.68 ms (+165%) | +10.27 ms (+145%) | 117 / 103 µs | 1 / 5 / 3 |

The `log()` rows are one plain insert plus the event, compared with the same
insert without it (1000 iterations each):

| Operation | plain p50 / p95 | `"log"` p50 / p95 | `"raise"` p50 / p95 | Added p50, `"log"` | Added p50, `"raise"` | Statements |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `log()` | 3.24 / 4.98 | 5.58 / 8.11 | 4.78 / 7.00 | +2.34 ms (+72%) | +1.54 ms (+47%) | 1 / 5 / 3 |
| durable `log()` | 5.63 / 7.04 | 12.37 / 15.05 | 12.31 / 15.31 | +6.73 ms (+119%) | +6.67 ms (+118%) | 1 / 3 / 3 |

Where the time goes:

- **The fixed cost is mostly round trips.** With the default
  `on_error="log"`, an audited flush sends four more statements than a
  plain one: a savepoint, the `audit_transaction` insert, the
  `audit_activity` insert, and the savepoint release. At 0.32 ms per
  round trip here, the round trips alone are about 1.3 ms of the 2.4 ms.
  The rest is the server work behind those statements (the savepoint, and
  inserts into two partitioned tables with their indexes), plus a little
  Python. The percentages look large because the baseline is small: one
  statement plus the commit.
- **What `on_error="raise"` saves:** the savepoint and its release. It
  measured 0.8 to 1.5 ms less than `"log"` at p50 in every insert, update
  and `log()` case. That is more than the two round trips alone (about
  0.6 ms), so the savepoint's server-side work counts too. The price is
  that a failed audit write (for example a missing partition) fails your
  transaction instead of being logged.
- **The per-object cost** at 100 objects is about 100 to 120 µs. A cProfile
  of the 100-object insert, taken separately from this run (and inflating
  Python time), put roughly half of the listener's time in the executemany
  of the 100 JSONB activity rows and about a third in building the diffs
  in Python.
- **A durable `log()`** commits on its own connection, so a request pays
  for a second transaction and a second commit. `on_error` changes nothing
  there (−0.06 ms): a durable write never uses the savepoint.
- **`disabled`** stays within 0.6 ms of `plain` at p50 (−2.5% to +8.0%).
  The differences go in both directions, which is noise at this scale. The
  mixin's `active_history` listeners have nothing to load here, because the
  rows were loaded before the change (see the protocol).

### Reads

5,000,000 `audit_activity` rows (4.38 GB with indexes) and 2,500,000
`audit_transaction` rows (0.56 GB), spread over 365 days. There are
4 severities × 16 months = 64 activity partitions (12 past months, the
current one and 3 ahead) and 16 transaction partitions. Each case ran 20
warm-up and 200 measured calls, each in its own session. Limit is 50
groups.

The last four columns come from one `EXPLAIN (ANALYZE)` run of every
statement the call sent:
- "Partitions read" counts distinct partitions actually executed.
- "Planned" sums the partition scans in the plans, including those pruned
  at run time.
- "Planning" and "Execution" are server-side milliseconds under EXPLAIN's
  instrumentation.

| Case | p50 ms | p95 ms | Groups | Statements | Partitions read (of 80) | Planned | Planning ms | Execution ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `list_groups` first page | 18.5 | 25.8 | 50 | 7 | 17 | 82 | 5.3 | 0.7 |
| `list_groups` first page, 30-day window | 15.1 | 19.7 | 50 | 7 | 17 | 27 | 2.3 | 0.4 |
| `list_groups` next page | 22.1 | 28.6 | 50 | 8 | 5 | 74 | 5.5 | 0.7 |
| `list_groups` next page, 30-day window | 17.4 | 23.2 | 50 | 8 | 5 | 19 | 2.8 | 0.7 |
| `list_groups` page 6 months back | 18.3 | 22.4 | 50 | 8 | 5 | 44 | 4.7 | 0.7 |
| `list_groups(actor_id=...)` | 22.1 | 33.7 | 50 | 4 | 65 | 121 | 7.8 | 2.7 |
| `object_history` (with children) | 21.5 | 25.8 | 50 | 4 | 68 | 148 | 9.4 | 1.9 |
| `access_summary`, whole history | 10.0 | 13.9 | — (367 entries counted) | 1 | 64 | 64 | 3.1 | 1.9 |

What this shows:

- **Data volume barely matters for pages.** `list_groups` runs one
  `LIMIT 51` query per severity. PostgreSQL reads each severity's monthly
  partitions newest first and stops once it has enough rows. The 17
  partitions read on a first page are 4 per severity plus one transaction
  partition. Of the 4 per severity, 3 are the empty partitions created
  ahead of time and 1 is the current month. A next page, or a page six
  months back, reads one partition per severity, because the cursor bounds
  `created_at` from above.
- **The window saves planning, not execution.** Without a lower bound, each
  per-severity query is planned over all 16 of its months and pruned at run
  time. With the 30-day window it is planned over 5. That is the 5.3 ms
  versus 2.3 ms planning, and most of the 3.4 ms latency difference on the
  first page. Planning cost grows with the number of partitions a query
  cannot exclude, so it grows with retention.
- **Most of the latency is client side.** The server executes these pages
  in under 1 ms. The rest is 7 or 8 round trips (about 2.5 ms here),
  planning, and Python: row decoding, grouping and compaction.
- **Where pruning cannot help.** `actor_id` without `severities`,
  `object_history` and `access_summary` filter on a column that is not a
  partition key, and have no time bound (`object_history` and
  `access_summary` ignore the default window by design). They must probe
  the index of every activity partition, all 64 of them. It stays fast here
  because each probe finds few rows. The cost grows with the number of
  partitions (months kept × severities), not with rows. Passing `since`
  bounds it.

## What these numbers are not

- **Not a comparison with other libraries.** Nothing else was measured.
- **Not a tuned server.** The PostgreSQL configuration is stock (128 MB
  `shared_buffers`, `synchronous_commit` on). The write baseline is
  dominated by commit fsync inside a WSL2 Docker VM. On real hardware, or
  with other durability settings, the plain baseline and the percentages
  will differ. The added round trips and per-object costs are the more
  portable numbers.
- **A mostly idle machine.** Other workloads were stopped for this run; one
  unrelated, idle PostgreSQL container was still running on the host.
- **Not concurrent.** One connection, sequential. Throughput columns in the
  JSON (`ops_per_s`, `objects_per_s`) are 1 / mean latency on that one
  connection, not server capacity.
- **Only sync psycopg.** `AsyncSession`/asyncpg is not measured.
- **Synthetic data.** The dataset is generated, with this deterministic
  skew: INFO 70%, NOTICE 20%, WARNING 8%, CRITICAL 2%. 10% of entries are
  `person.viewed` on 1,000 people. The rest are `entity.created` /
  `updated` / `deleted` on 9 object types × 100,000 ids, 20% of them with
  an `Order` target (5,000 ids). There are 1,000 actors and 50 scopes, and
  1 to 3 entries per transaction. Real logs have other shapes. In
  particular, a rare severity makes its per-severity query read further
  back.
- **Not cold-cache reads.** Each case runs warm-up calls first. The page
  cache holds whatever seeding and warm-up left in it, and cold-cache reads
  of the 4.9 GB dataset are not measured.

## Protocol

**Write variants.**
- `plain`: a model without `Audited`, on a session class the library is not
  installed on. This is the true zero and the baseline for every
  percentage.
- `disabled`: the `Audited` model (same columns) on the installed session
  class, with `session.info["audit_enabled"] = False`. The mixin's
  `active_history` listeners and the session listeners still run, but no
  entries are written. This answers "what does leaving it installed but off
  cost".
- `audited`: the `Audited` model on the installed session class, capturing
  inside an `audit.context(...)`, with the default `on_error="log"`: the
  audit inserts run in a savepoint, so a failed audit write does not fail
  the transaction.
- `audited_raise`: the same with an `AuditTrail(on_error="raise")`,
  installed on its own session class: no savepoint.

Before measuring, the runner checks that each variant is what it claims to
be, and stops if not:
- the plain model is not `Audited`;
- the plain session class has no trail installed;
- each audited session has the expected trail, `on_error` and capture
  flag.

The checks that passed are listed under `write.preconditions` in the JSON.

**Write operations.** Each operation is one transaction ended by `commit()`.
- Insert: `add_all(n new objects)` + `commit()`. The objects are built
  outside the timer.
- Update: the same n rows are loaded in the session's transaction outside
  the timer, then two columns are changed and `commit()` runs, all timed.
- `log()`: one plain insert, then `audit.log(session, event,
  payload=...)`, then `commit()`. The events use `benchmark.*` verbs and are
  defined only when the write benchmark runs, never at import.
- Durable `log()`: the same, with an event declared `durable=True`.

The variants of a case run in interleaved blocks of 50, after warm-up, so
drift from table growth or autovacuum falls on all of them. Write tables and
audit tables start empty and are separate from the read dataset.

**Read dataset.** It is seeded with one `INSERT ... SELECT` over
`generate_series` per table, not through the ORM. Each activity row's
`created_at` equals its transaction's `issued_at`, as the library writes
them. `VACUUM (ANALYZE)` runs afterwards. The runner creates its own schemas
and drops them at the end (`--keep` keeps them).

**Partitions.** A listener captures every `SELECT` a call sends. Each one is
then re-run as `EXPLAIN (ANALYZE, FORMAT JSON)` with the same parameters, on
the same connection and in the same transaction, after the library's
`SET LOCAL plan_cache_mode = 'force_custom_plan'`. This needs no superuser.

## Rerun

Needs Docker, or an existing server:

```bash
uv sync --frozen
uv run python -m benchmark.run_benchmark                    # postgres:18 in Docker, ~12 min
uv run python -m benchmark.run_benchmark --image postgres:14
uv run python -m benchmark.run_benchmark --database-url postgresql://user:pw@host/db
```

With `--database-url`, the runner creates schemas named `bench_<id>_*` and
drops them afterwards. The URL's driver is replaced with psycopg.

Quick check (seconds):

```bash
uv run python -m benchmark.run_benchmark --iterations 20 --iterations-large 10 \
  --warmup 5 --activity-rows 20000 --read-iterations 5
```

| Flag | Default | |
| --- | --- | --- |
| `--database-url` | none | use this server instead of a container |
| `--image` | `postgres:18` | container image |
| `--batch-sizes` | `1,10,100` | objects per flush |
| `--iterations` / `--iterations-large` | 1000 / 300 | measured writes; the second for batches ≥ `--large-batch` (100) |
| `--warmup` / `--block` | 100 / 50 | warm-up writes per variant; interleaving block |
| `--activity-rows` | 5,000,000 | read dataset size (transactions = half) |
| `--read-iterations` / `--read-warmup` | 200 / 20 | calls per read case |
| `--skip-write` / `--skip-read` | off | run one half only |
| `--keep` | off | keep the benchmark schemas |
| `--output-dir` | `benchmark/results/` | where the JSON goes |

`tests/db/test_benchmark.py` runs the whole runner at tiny sizes in the test
suite, so the script keeps working between full runs.
