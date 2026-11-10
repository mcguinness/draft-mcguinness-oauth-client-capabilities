# Test Vectors

Parsing test vectors for draft-mcguinness-oauth-client-capabilities. They are
kept here rather than in the draft until the open question on size limits is
settled. Section names refer to the
draft. Each row applies the rules of the specification to one input, and names
the rule where it is not obvious. The values `a`, `b` and `c` are placeholders
that the server recognizes.

## Request Parameter

The client's metadata declares the default `["a"]`. Values are shown after
form decoding.

| Parameter value | Effective set | Rule |
|---|---|---|
| (omitted) | a | Metadata default, step 2 of "Precedence" |
| (empty value) | a | An empty value is treated as omitted |
| `b c` | b, c | |
| `c b b` | b, c | Order and duplicates are ignored |
| `none` | (empty) | Retracts the default |
| `none b` | (empty) | `none` with other values |
| `b,c` | (empty) | Invalid: a comma is not allowed |
| `b` and `c` two spaces apart | (empty) | Invalid: repeated spaces |
| `*b` | (empty) | Invalid: does not start with a letter |
| A list over the server's limit | (empty), or the request is rejected | "Denial of Service" |
*Request parameter test vectors*

With a Request Object, and the same metadata default:

| In the Request Object | Outside it | Effective set |
|---|---|---|
| `"client_capabilities": "b c"` | (absent) | b, c |
| `"client_capabilities": ["b", "c"]` | (absent) | (empty): invalid, not a string |
| (absent) | `client_capabilities=b` | a: the outside value is not used |
*Request Object test vectors*

## HTTP Field

Without out-of-band knowledge:

| Field value | Effective set | Rule |
|---|---|---|
| (absent) | (empty) | |
| (empty field value) | (empty) | An empty List is treated as absent |
| `b, c` | b, c | |
| `b;x=1` | b | Parameters are ignored |
| `b, none` | (empty) | `none` with other members |
| `b c` | (empty) | Invalid: not a Structured Fields List |
| `"b"` | (empty) | Invalid: a String member |
| `(b c)` | (empty) | Invalid: an Inner List member |
| `*b` | (empty) | Invalid: violates the `capability` production |
*HTTP field test vectors*

When the server knows out of band that the client supports `a`:

| Field value | Effective set | Rule |
|---|---|---|
| (absent) | a | Out-of-band knowledge applies |
| (empty field value) | a | Treated as absent |
| `b` | b | A valid field replaces out-of-band knowledge |
| `x`, which the server does not recognize | (nothing recognized) | A valid field replaces out-of-band knowledge |
| `none` | (empty) | Retracts out-of-band knowledge |
| `none, b` | (empty) | `none` with other members |
| `none, "b"` | a | Invalid, so treated as absent |
| A list over the server's limit | a, or the request is rejected | Treated as invalid ("Denial of Service") |
*HTTP field test vectors with out-of-band knowledge*

## Client Metadata

An invalid field yields no capabilities; the metadata protocol determines
whether the document or request is rejected or the field ignored
("Client Metadata Declaration").

| Metadata value | Default set |
|---|---|
| `["b", "c"]` | b, c |
| `[]` | (empty) |
| `["none"]` | Invalid: contains `none` |
| `["b c"]` | Invalid: an element contains a space |
| `["b", 1]` | Invalid: an element is not a string |
*Client metadata test vectors*
