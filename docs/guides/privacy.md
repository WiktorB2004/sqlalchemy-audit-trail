# Privacy and GDPR

An audit log collects personal data by design: who did what, from which address, to whose record. The library gives you several layers, in this order of preference:

1. **Don't store it**: `exclude` columns that the log does not need.
2. **Store a token**: `hash` columns and `Pseudonymized` payload fields keep values correlatable without keeping them.
3. **Mask it**: `redact` columns record that a value changed, not the value.
4. **Erase it afterwards**: `scrub` and `scrub_actor`, the only updates the library ever makes to audit rows.

Retention (see [partitions](partitions.md#retention)) is the last layer: every entry, with its context snapshot, disappears when its partition expires.

## Column policies

See [audited models](models.md#column-policies). Column names are not a redaction mechanism: `check_models()` reports columns that look sensitive and have no explicit policy, so each one is a decision.

## Keys and rotation

The `hash` policy and pseudonymized values are HMAC-SHA256 tokens under `AuditTrail(pseudonymize_key=...)`. A key must be at least 32 bytes. Keep it secret: anyone with the key can test guesses against the tokens.

```python
audit = AuditTrail(engine, pseudonymize_key=os.environ["AUDIT_KEY"].encode())
```

A token carries its key version in its prefix: `hv1:<hex>` for a hashed column, `audit.<purpose>.v1:<hex>` for `pseudonymize(value, purpose=...)`. To rotate, pass a mapping of versions and keep the old keys for as long as old rows should stay correlatable:

```python
audit = AuditTrail(engine, pseudonymize_key={1: old_key, 2: new_key})
```

New tokens use the highest version. `verify()` checks a stored token against a candidate value with the key of the token's version; it returns `False`, without raising, when that key is no longer kept:

```python
from audit_trail.serialization import verify

verify(stored_token, "ada@example.com", keys=audit.keys)
```

`None` is never hashed: a null value stays `null`.

## Actor ids

`actor_id` is meant to be an opaque internal identifier (a user's primary key or UUID), not an e-mail address or a login. It is an indexed column, and `scrub_actor` deliberately leaves it in place: clearing it would break "what did this actor do" queries for good. Personal details belong in `actor_label` and the other context fields, which can be scrubbed. If you store personal data in `actor_id`, it stays in the log for as long as the entries are kept.

## Scrubbing

Scrubbing is off unless you enable it, and it needs a database role allowed to update the audit tables (see [roles](permissions.md)). Usually that is a separate `AuditTrail` used by an admin task, not the one your request handlers use:

```python
maintenance = AuditTrail(maintenance_engine, allow_scrub=True, events=[])
```

### An object's values

```python
from audit_trail.diff import object_id_for

result = maintenance.scrub("Customer", object_id_for(Customer, 17))
print(result.activity_rows)
```

`scrub(object_type, object_id, *, include_targets=True, since=None)` replaces every non-null value in `data["changes"]` and `data["payload"]` of the object's entries with `"[erased]"` and sets `object_label` to `NULL`. Field names stay, so the history still shows *that* something changed; `null` stays `null`. With `include_targets`, entries whose target is the object (the changes of its children) are erased too. `since`, a timezone-aware datetime, limits the scrub to newer entries and to fewer partitions. The context snapshots are left alone; that is what `scrub_actor` is for.

### An actor's context

```python
result = maintenance.scrub_actor("17")
print(result.transaction_rows, result.activity_rows)
```

`scrub_actor(actor_id)` sets `actor_label`, `remote_addr`, `user_agent` and `meta` to `NULL` on the `audit_transaction` rows created with this actor, and removes the same keys from `data["context"]` of the actor's entries. `actor_id` stays. A transaction row belongs to the actor it was created with: a request that wrote its first entry anonymously and set the actor afterwards keeps its address on that anonymous row.

Both return a `ScrubResult(activity_rows, transaction_rows)` with the numbers of rows changed; rows already scrubbed are not counted again. Both run in one transaction on the `AuditTrail`'s engine, together with an `audit.scrubbed` entry recording who scrubbed what and how many rows, without any erased value. The entry's severity is `system_severity`. Without `allow_scrub=True` they raise `ScrubNotAllowedError`. For an `AuditTrail` on an async engine, use `ascrub()` and `ascrub_actor()`.
