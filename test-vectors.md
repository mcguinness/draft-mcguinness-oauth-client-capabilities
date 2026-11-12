# Test Vectors

Parsing test vectors for draft-mcguinness-oauth-client-capabilities, kept here
rather than in the draft for the -00 submission. Section names refer to the
draft. Each row applies the rules of the specification to one input, and names
the rule where it is not obvious. The values `a`, `b` and `c` are placeholders
that the server recognizes; `x` and `B` are values it does not recognize.
`none` is never recognized, so a set containing only `none` is shown as
(empty).
Signals are within the size limits in "Limits" unless a row says
otherwise.

## Request Parameter

The client's metadata declares the default `["a"]`. Values are shown after
form decoding.

| Parameter value | Effective set | Rule |
|---|---|---|
| (omitted) | a | Metadata default, step 2 of "Determining the Effective Capability Set" |
| (empty value) | a | An empty value is treated as omitted |
| `b c` | b, c | |
| `c b b` | b, c | Order and duplicates are ignored |
| `B` | B, not recognized | Values are case-sensitive |
| `none` | (empty) | Overrides the default for this request |
| `none b` | b | `none` is not recognized; a sender must not mix it with other values |
| `b,c` | (empty) | Invalid: a comma is not allowed |
| `b` and `c` two spaces apart | (empty) | Invalid: repeated spaces |
| `*b` | (empty) | Invalid: does not start with a letter |
| 64 members, within 4096 octets | all 64 | Within the size every server admits |
| A list over the server's limit | (empty), or the request is rejected | "Limits" |
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

With a Request Object, and the same metadata default:

| In the Request Object | Outside it | Effective set |
|---|---|---|
| `"client_capabilities": "b c"` | (absent) | b, c |
| `"client_capabilities": ["b", "c"]` | (absent) | (empty): invalid, not a string |
| `"client_capabilities": null` | (absent) | (empty): invalid, not a string |
| `"client_capabilities": ""` | (absent) | a: an empty string is treated as omitted |
| `"client_capabilities": "none"` | (absent) | (empty): overrides the default for this request |
| `"client_capabilities": "\u0062 \u0063"` | (absent) | b, c: escapes are decoded before the value is parsed |
| One value of 1,000 `a` characters, unescaped: 1,002 octets | (absent) | That value, not recognized |
| The same value as 1,000 `\u0061` escapes: 6,002 octets | (absent) | (empty), or the request is rejected, where the server's limit is 4096 octets: the serialized escapes are counted ("Limits") |
| (absent) | `client_capabilities=b` | a: the outside value is not used |
*Request Object test vectors*

A pushed authorization request is form-encoded (RFC 9126, Section 2), so the
request parameter and form-encoded vectors above apply to the value it carries.
The Request Object vectors apply only when it carries a Request Object (RFC
9126, Section 3). Such a request has to carry every authorization parameter
inside the Request Object, so a value outside it, as in the last Request Object
row, is not allowed there; it is still not used. With the same metadata
default:

| Pushed request | Authorization request | Effective set |
|---|---|---|
| `client_capabilities=b` | `request_uri` and `client_capabilities=c` | b: a value sent alongside the `request_uri` is not used |
| No `client_capabilities` | `request_uri` and `client_capabilities=c` | a: the pushed request has no value, so the default applies |
| `request` holding a Request Object with `"client_capabilities": "b"` | `request_uri` | b |
*Pushed authorization request test vectors*

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
| A list over the server's limit | a, or the request is rejected | Treated as invalid ("Limits") |
*HTTP field test vectors with out-of-band knowledge*

## Request Classification

Unless a row says otherwise, each request carries
`OAuth-Client-Capabilities: b` and no `client_capabilities` parameter; the
client's metadata declares the default `["a"]`, and no out-of-band knowledge
applies. The kind of request decides which carrier counts and what the default
is (the kinds of request in "Determining the Effective Capability Set").
Authorization with an access token does not change the kind.

| Request | Kind | Effective set |
|---|---|---|
| UserInfo request with an access token | Protected resource request | b |
| UserInfo request with an access token and no field | Protected resource request | (empty): client metadata is never the default |
| Request to a resource server with an access token | Protected resource request | b |
| Token request (the client must not send the field) | Request to a parameter endpoint; the field is ignored | a |
| Introspection request authorized with a bearer token | Other; the field plays no part | No effective set, unless an extension defines the parameter there |
| Registration request with an initial access token | Other; the field plays no part | No effective set: the request's metadata declares the default |
| Client configuration request with a registration access token | Other; the field plays no part | No effective set: the client's metadata declares the default |
*Request classification test vectors*

## Client Metadata

An invalid field is ignored and yields no capabilities. An otherwise-valid
document or registration request is not rejected because of it. The one
exception is a field that exceeds the server's size limit in a registration
request. A Client ID Metadata Document is not rejected for an oversized field,
but it can still be rejected when the whole document exceeds the server's
retrieval or parsing limits ("Client Metadata Declaration", "Limits").

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
| `"a"` 65 times, without whitespace: 261 octets | a; or, where the server's limit is 64 members, (empty) or the registration request is rejected | Members are counted before duplicates are removed ("Limits") |
| The same array in a Client ID Metadata Document | a; or, where the server's limit is 64 members, (empty) | The document is not rejected for the field ("Limits") |
| A 4,096-octet array in a Client ID Metadata Document that is over 5 KB in all | None, where the server stops reading at 5 KB as CIMD Section 10.11 recommends: the document is rejected | Whole-document limits still apply, even when the field accounts for most of the size |
*Client metadata test vectors*

## Discovery

An invalid `client_capabilities_supported` member is ignored in its entirety
("Discovery"). A client that has a valid list should signal only values in it,
sending `none` where it needs to override a default.

| `client_capabilities_supported` | Values a client signals |
|---|---|
| `["a", "b"]` | Only a and b, or `none` where it must override |
| `[]` | Nothing, or `none` where it must override |
| `["a", "none"]` | Only a, or `none` where it must override; the server must not list `none` |
| `"a"` | List ignored: not an array |
| `["a", "*b"]` | List ignored: an element violates the `capability` production |
*Discovery test vectors*
