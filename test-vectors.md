# Test Vectors

Parsing test vectors for draft-mcguinness-oauth-client-capabilities. They are
kept here rather than in the draft until the open questions on limits and on
retraction at a protected resource are settled. Section names refer to the
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

No out-of-band knowledge applies.

| Field value | Effective set | Rule |
|---|---|---|
| (absent) | (empty) | |
| `b, c` | b, c | |
| `b;x=1` | b | Parameters are ignored |
| `b, none` | b | A `none` member is ignored |
| `b c` | (empty) | Invalid: not a Structured Fields List |
| `"b"` | (empty) | Invalid: a String member |
| `(b c)` | (empty) | Invalid: an Inner List member |
| `*b` | (empty) | Invalid: violates the `capability` production |
*HTTP field test vectors*

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

 
 This appendix is informative and describes how the two extensions that
