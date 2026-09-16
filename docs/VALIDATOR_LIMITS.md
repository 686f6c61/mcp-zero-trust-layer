# Validator contracts and limits

Validators enforce the documented input subset before forwarding a request. They complement upstream authorization, schemas and confinement; they do not establish that every possible action in every implementation is harmless.

## SQL read-only guardrail

`sql_read_only` accepts a conservative lexical subset starting with `SELECT`, `WITH` or `EXPLAIN`. It rejects stacked statements, destructive/control keywords, executable comments, locking syntax (`FOR`), sequence advancement syntax (`NEXT`), and unrecognized function calls. A trailing semicolon is allowed. Plain `WITH name AS (SELECT ...)` CTEs are supported; dialect extensions and CTE column declarations may be rejected.

String literals use single quotes with standard doubled-quote escaping. Ordinary line/block comments and double-quoted identifiers are supported. Comment markers and semicolons inside strings do not hide subsequent SQL. Backslash escapes, dollar quoting, backticks, bracket identifiers, nested comments, executable comments and unterminated quotes/comments are rejected because their interpretation differs across SQL dialects. Destructive words inside ordinary string literals do not themselves cause rejection.

Permitted unqualified function names are:

`abs`, `avg`, `ceil`, `ceiling`, `coalesce`, `count`, `floor`, `length`, `lower`, `ltrim`, `max`, `min`, `nullif`, `round`, `rtrim`, `substr`, `substring`, `sum`, `trim`, `upper`.

Other functions, quoted function names and schema-qualified function calls are rejected. This intentionally blocks sequence mutation, advisory locks, configuration changes, external I/O and unknown user-defined functions instead of trying to enumerate every dangerous function. There is no option to bypass this function restriction through an untrusted request.

This is a lexical guardrail, not a dialect-aware SQL parser or a proof of side-effect freedom. Function/operator overloads, search paths, views, extensions and database-specific semantics remain outside its guarantee. Use a database role/connection with enforced read-only permissions, a trusted schema/search path, restricted function privileges and resource limits. For unsupported legitimate syntax, use a purpose-built upstream tool with a constrained interface; do not disable database read-only enforcement.

## Email recipients

Each recipient value must be one canonical mailbox address (`user@example.com`). Multiple recipients must be supplied as a JSON list of individual mailbox strings. Comma/semicolon recipient header strings, display-name forms, comments and CR/LF header injection are rejected. Domain allow/block rules compare normalized lowercase exact domains; they do not implicitly allow subdomains.

The validator examines `recipients_arg`, defaulting to `to`. Configure additional email validators with `recipients_arg: cc` and `recipients_arg: bcc` when the tool supports those fields; constrain other recipient-bearing fields through input policy/schema. Do not assume validating `to` also validates independently named recipients. Attachment blocking applies to the `attachments` argument when enabled.

## Nested allowed fields

`allowed_fields: [customer.name]` requires any present `customer` value to be an object and permits only the specified descendant path. An array, scalar or null at that ancestor is rejected rather than bypassing descendant validation. This does not require the leaf to be present; use `required_fields` for that.

Explicitly allowing `customer` permits its whole subtree, including arrays. Dotted paths do not provide array-element wildcard semantics. Use a schema or dedicated validator for structured lists requiring restrictions on each item.
