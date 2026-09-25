# Changelog

## Unreleased

- `AuditContext` and `Actor`: request context set with `context()`, updated in place with `set_actor()`, or attached to one session with `bind()`
- Value serialization for audit entries and keyed HMAC pseudonyms with versioned keys; `Pseudonymized[...]` marks payload fields
