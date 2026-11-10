# Test Vectors

Parsing test vectors for draft-mcguinness-oauth-client-capabilities, kept here
rather than in the draft for the -00 submission. Section names refer to the
draft. Each row applies the rules of the specification to one input, and names
the rule where it is not obvious. The values `a`, `b` and `c` are placeholders
that the server recognizes; `x` and `B` are values it does not recognize.
`none` is never recognized, so a set containing only `none` is shown as
(empty).
Signals are within the size limits in "Denial of Service" unless a row says
otherwise.

## Request Parameter

The client's metadata declares the default `["a"]`. Values are shown after
form decoding.

| Parameter value | Effective set | Rule |
|---|---|---|
| (omitted) | a | Metadata default, step 2 of "Precedence" |
| (empty value) | a | An empty value is treated as omitted |
| `b c` | b, c | |
| `c b b` | b, c | Order and duplicates are ignored |
| `B` | B, not recognized | Values are case-sensitive |
| `none` | (empty) | Retracts the default |
| `none b` | b | `none` is not recognized; a sender must not mix it with other values |
| `b,c` | (empty) | Invalid: a comma is not allowed |
| `b` and `c` two spaces apart | (empty) | Invalid: repeated spaces |
| `*b` | (empty) | Invalid: does not start with a letter |
| 64 members, within 4096 octets | all 64 | Within the size every server admits |
| A list over the server's limit | (empty), or the request is rejected | "Denial of Service" |
*Request parameter test vectors*

The same metadata default, with the form-encoded request shown before decoding:

| Form-encoded request | Effective set | Rule |
|---|---|---|
| `client_capabilities=b+c` | b, c | `+` decodes to a space |
| `client_capabilities=b%20c` | b, c | |
| `client_capabilities=b++c` | (empty) | Invalid after decoding: repeated spaces |
| `client_capabilities=` | a | An empty value is treated as omitted |
| `client_capabilities=b&client_capabilities=c` | Request rejected with `invalid_request` | A repeated parameter is malformed |
*Form-encoded request test vectors*

With a Request Object or a pushed request, and the same metadata default:

| In the Request Object or pushed request | Outside it | Effective set |
|---|---|---|
| `"client_capabilities": "b c"` | (absent) | b, c |
| `"client_capabilities": ["b", "c"]` | (absent) | (empty): invalid, not a string |
| `"client_capabilities": null` | (absent) | (empty): invalid, not a string |
| `"client_capabilities": ""` | (absent) | a: an empty string is treated as omitted |
| `"client_capabilities": "none"` | (absent) | (empty): retracts the default |
| `"client_capabilities": "\u0062 \u0063"` | (absent) | b, c: escapes are decoded before the value is parsed |
| One value of 1,000 `a` characters, unescaped: 1,002 octets | (absent) | That value, not recognized |
| The same value as 1,000 `\u0061` escapes: 6,002 octets | (absent) | (empty), or the request is rejected, where the server's limit is 4096 octets: the serialized escapes are counted ("Denial of Service") |
| (absent) | `client_capabilities=b` | a: the outside value is not used |
| Pushed `client_capabilities=b`, used through `request_uri` | `client_capabilities=c` alongside the `request_uri` | b: the value sent alongside is not used |
*Request Object test vectors*

## HTTP Field

Without out-of-band knowledge:

| Field value | Effective set | Rule |
|---|---|---|
| (absent) | (empty) | |
| (empty field value) | (empty) | An empty List is treated as absent |
| `b, c` | b, c | |
| `b, b` | b | Duplicates are ignored |
| `b` on one field line and `c` on another | b, c | Field lines are combined |
| `B` | B, not recognized | Values are case-sensitive |
| `b;x=1` | b | Parameters are ignored |
| `b, none` | b | `none` is not recognized; a sender must not mix it with other members |
| `none;x=1` | (empty) | Parameters are ignored, leaving `none` |
| `b,` | (empty) | Invalid: trailing comma |
| `b c` | (empty) | Invalid: not a Structured Fields List |
| `"b"` | (empty) | Invalid: a String member |
| `(b c)` | (empty) | Invalid: an Inner List member |
| `*b` | (empty) | Invalid: violates the `capability` production |
| `?1` | (empty) | Invalid: a Boolean member, as `Accept-Txn-Challenge` sends |
| `:YQ==:` | (empty) | Invalid: a Byte Sequence member |
| `b` on one field line and `"c"` on another | (empty) | Invalid: the combined value has a String member |
*HTTP field test vectors*

When the server knows out of band that the client supports `a`:

| Field value | Effective set | Rule |
|---|---|---|
| (absent) | a | Out-of-band knowledge applies |
| (empty field value) | a | Treated as absent |
| `b` | b | A valid field replaces out-of-band knowledge |
| `x` | x, not recognized | A valid field replaces out-of-band knowledge |
| `none` | (empty) | A valid field replaces out-of-band knowledge |
| `none, b` | b | A valid field replaces out-of-band knowledge; `none` is not recognized |
| `none, "b"` | a | Invalid, so treated as absent |
| `none` repeated until the value exceeds the server's limit | a, or the request is rejected | Over the limit, so invalid |
| A list over the server's limit | a, or the request is rejected | Treated as invalid ("Denial of Service") |
*HTTP field test vectors with out-of-band knowledge*

## Request Classification

Unless a row says otherwise, each request carries
`OAuth-Client-Capabilities: b` and no `client_capabilities` parameter; the
client's metadata declares the default `["a"]`, and no out-of-band knowledge
applies. The kind of request decides which carrier counts and what the default
is (the kinds of request in "Precedence"). Authorization with an access token
does not change the kind.

| Request | Kind | Effective set |
|---|---|---|
| UserInfo request with an access token | Protected resource request | b |
| UserInfo request with an access token and no field | Protected resource request | (empty): client metadata is never the default |
| Request to a resource server with an access token | Protected resource request | b |
| Token request (the client must not send the field) | OAuth request; the field is ignored | a |
| Introspection request authorized with a bearer token | Other; the field plays no part | No effective set, unless an extension defines the parameter there |
| Registration request with an initial access token | Other; the field plays no part | No effective set: the request's metadata declares the default |
| Client configuration request with a registration access token | Other; the field plays no part | No effective set: the client's metadata declares the default |
*Request classification test vectors*

## Client Metadata

An invalid field is ignored and yields no capabilities. An otherwise-valid
document or registration request is not rejected because of it, unless the
field exceeds the server's size limit ("Client Metadata Declaration", "Denial
of Service").

| Metadata value | Default set | Rule |
|---|---|---|
| `["b", "c"]` | b, c | |
| `["b", "b"]` | b | |
| `[]` | (empty) | |
| `["none"]` | (empty) | A sender must not include `none`; a recipient does not recognize it |
| `["none", "b"]` | b | A sender must not include `none`; a recipient does not recognize it |
| `["b c"]` | (empty) | Invalid: an element contains a space |
| `["b", 1]` | (empty) | Invalid: an element is not a string |
| `"b"` | (empty) | Invalid: not an array |
| `"a"` 64 times, without whitespace: 257 octets | a | Within the size every server admits |
| `"a"` 65 times, without whitespace: 261 octets | a; or, where the server's limit is 64 members, (empty) or the registration request is rejected | Members are counted before duplicates are removed ("Denial of Service") |
*Client metadata test vectors*

## Discovery

An invalid `client_capabilities_supported` member is ignored in its entirety
("Discovery"). A client that holds a valid list should signal only values in
it, sending `none` where it needs to override a default.

| `client_capabilities_supported` | Values a client signals |
|---|---|
| `["a", "b"]` | Only a and b, or `none` where it must override |
| `[]` | Nothing, or `none` where it must override |
| `["a", "none"]` | Only a, or `none` where it must override; the server must not list `none` |
| `"a"` | List ignored: not an array |
| `["a", "*b"]` | List ignored: an element violates the `capability` production |
*Discovery test vectors*
