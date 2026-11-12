---
title: "OAuth 2.0 Client Capabilities"
abbrev: oauth-client-capabilities
docname: draft-mcguinness-oauth-client-capabilities-latest
category: std

ipr: trust200902
area: "Security"
workgroup: "Web Authorization Protocol"

keyword:
 - OAuth
 - Client Capabilities
 - Extension Negotiation
 - Capability Signaling
 - Open World

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: K. McGuinness
    name: Karl McGuinness
    org: Independent
    email: public@karlmcguinness.com

normative:
  RFC5234:
  RFC6749:
  RFC7591:
  RFC8126:
  RFC8414:
  RFC9101:
  RFC9110:
  RFC9126:
  RFC9651:
  RFC9728:

informative:
  RFC3261:
  RFC7240:
  RFC7120:
  RFC9207:
  RFC7009:
  RFC7592:
  RFC7662:
  RFC8628:
  RFC8942:
  RFC9396:
  RFC9449:
  RFC9635:
  RFC9700:
  RESOURCE-TOKEN-RESP: I-D.mcguinness-oauth-resource-token-resp
  OAUTH21-VERSIONS:
    target: https://github.com/oauth-wg/oauth-v2-1/issues/120
    title: "How can an AS support both 2.0 and 2.1 clients concurrently"
  OAUTH21: I-D.ietf-oauth-v2-1
  DTR: I-D.ietf-oauth-deferred-token-response
  TXN-CHALLENGE: I-D.rosomakho-oauth-txn-challenge
  CIMD: I-D.ietf-oauth-client-id-metadata-document
  FIRST-PARTY-APPS: I-D.ietf-oauth-first-party-apps
  ABCA: I-D.ietf-oauth-attestation-based-client-auth
  IANA-OAUTH:
    target: https://www.iana.org/assignments/oauth-parameters/
    title: "OAuth Parameters"
  FETCH:
    target: https://fetch.spec.whatwg.org/
    title: "Fetch Living Standard"
  OIDC:
    target: https://openid.net/specs/openid-connect-core-1_0.html
    title: "OpenID Connect Core 1.0"

--- abstract

OAuth 2.0 extensions increasingly require an authorization server or protected
resource to know, before it acts, whether the client is able to process a
particular protocol behavior. Extensions define this signal individually today,
and the two carriers in use are not interchangeable: the OAuth front channel is
mediated by a user agent and cannot carry a client-originated HTTP field, while
a protected resource request has no OAuth request parameter surface.

This document defines a single registry of client capability values and three
carriers for them: a `client_capabilities` request parameter, an
`OAuth-Client-Capabilities` HTTP field, and a `client_capabilities` client
metadata field. Capability values are advisory and are constrained to enable
only optional server behavior, so that adding or removing a value does not
weaken security. Because each request can carry its own set, a client can roll
out a capability one instance, release, or authorization server at a time,
without changing metadata that every instance shares.

--- middle

# Introduction {#intro}

A growing number of OAuth 2.0 {{RFC6749}} extensions share one normative shape:

> The server MUST NOT do X unless the client has signaled that it can process X.

These extensions change what a client receives in response to an otherwise
ordinary request, and a client that cannot process the new response fails.

Two current extensions illustrate the pattern, and disagree on how to carry it.
{{DTR}} requires an authorization server not to defer a response unless the
`completion_mode` request parameter includes `deferred`. {{TXN-CHALLENGE}}
requires a protected resource not to return a transaction authorization
challenge unless `Accept-Txn-Challenge` is true or support is known out of
band.

The requirements are structurally identical. The carriers are not.

## Overview {#overview}

A client tells a server what optional behavior it can process by signaling
capability values. A capability value is a short token drawn from a single
registry ({{iana-registry}}) shared by every extension.

Three carriers convey a set, chosen by what the request can hold:

- The `client_capabilities` request parameter, on OAuth requests such as
  authorization and token requests ({{param}}).
- The `OAuth-Client-Capabilities` HTTP field, on protected resource requests
  ({{field}}).
- A `client_capabilities` member in client metadata, supplying a default when an
  OAuth request carries no signal ({{metadata}}).

Whichever carrier applies, the result is the request's effective capability
set: the values a server may act upon for that request. A request-level signal
replaces any metadata default rather than adding to it ({{precedence}}).

A server advertises the values it recognizes in its own metadata
({{discovery}}). Signaling never obliges a server to act. Under the invariants
in {{invariants}}, which every registered value has to meet, a signal that is
absent, removed, added, or untrue leaves the protocol no less secure.

## The Carrier Asymmetry {#asymmetry}

Neither carrier can perform the other's function. An HTTP field works for
{{TXN-CHALLENGE}} because the protected resource request is made directly over
HTTP, but that request has no OAuth parameter surface. At the authorization
endpoint, the client constructs a URI for a user agent, which issues the HTTP
request with its own fields; a client-originated field cannot cross that
redirect boundary.

A general mechanism cannot be an HTTP field alone, and cannot be a request
parameter alone. Two request carriers over one shared vocabulary is the minimum
that covers OAuth's topology.

The extensions in {{existing-drafts}} need only direct HTTP requests, at the
token endpoint and at protected resources. Even at the token endpoint, the
request parameter is the carrier rather than the field: OAuth endpoints are
extended through registered request parameters, as {{DTR}} already does, and
one carrier at each endpoint where the parameter is defined lets a request
override a client metadata default without combining two signals. The request
parameter's coverage of the authorization endpoint anticipates extensions whose
behavior changes the authorization response; the pushed authorization request
and Request Object examples ({{examples}}) illustrate the carrier.

## Open-World Deployment {#open-world}

Classic OAuth establishes client behavior at registration. Metadata fields such
as `grant_types`, `response_types`, `token_endpoint_auth_method`,
`dpop_bound_access_tokens` {{RFC9449}}, and
`require_pushed_authorization_requests` {{RFC9126}} provide a static
declaration {{RFC7591}}.

Deployments that identify clients by a published metadata document {{CIMD}},
operate autonomous software instances, or otherwise pair previously unknown
clients and authorization servers have no registration handshake. The first
request must carry the relevant capability or the server must discover it from
client-published metadata.

A published document is also shared. It applies to every instance using the
URL, and a change to it reaches each authorization server only as that server
refreshes its cached copy, on a schedule the publisher cannot target {{CIMD}}.
A change therefore cannot be staged one authorization server or one release at
a time, and rolling it back waits out the same caches. A request-level signal
avoids both ({{staged-rollout}}).

Per-extension signals accumulate in both directions. Each front-channel
capability can enlarge an authorization URI visible to the user agent. Each
resource capability adds a field to protected resource requests. A
per-extension signal also needs its own registrations and metadata. A shared
vocabulary incurs those costs once across both sides of the asymmetry in
{{asymmetry}}.

## Scope {#scope}

This specification defines carriers and a vocabulary, and reserves the `none`
sentinel ({{none-value}}). It does not define any capability values, change any
existing parameter, or require existing extensions to migrate. The extensions
in {{existing-drafts}} are the intended first adopters; this specification
proposes the mechanism for their use rather than registering values on their
behalf.

Two uses are out of scope. Capability values do not carry deployment-local
feature flags or rollout cohort membership, whoever assigns it, because neither
describes what a client can process. A client may use its own cohorts to decide
which values to signal, which is how it stages adoption ({{staged-rollout}});
the cohort itself is not signaled. Nor do capability values signal conformance
to a requirement, in either direction. A claim of conformance cannot be
verified and can be omitted by anyone who would violate the requirement, so
enforcement keys on the client's identity rather than the claim. A claim of
non-conformance cannot be sent by the clients that need it, which generally
cannot be updated to send anything.

# Conventions and Definitions {#terms}

{::boilerplate bcp14-tagged}

Capability:
: A named behavior that a client asserts it can process and that a server may
  choose to exercise.

Signal:
: To convey capability values to a server through one of the carriers defined
  in {{carriers}}; as a noun, the values so conveyed.

Recognize:
: A recipient recognizes a capability value when it implements what the value
  names: the server behavior, or, for a client reading a server's list, the
  client processing. The reserved token `none` names nothing and is never
  recognized.

Effective capability set:
: The capability set that applies to a request after the carrier and precedence
  rules in {{carriers}} have been applied. Also called the effective set.

Request-level signal:
: The signal carried on the request itself: the request parameter on an OAuth
  request, or the HTTP field on a protected resource request ({{precedence}}).
  Client metadata supplies a default, not a request-level signal.

Out-of-band knowledge:
: Knowledge, where an extension defines it, that a protected resource has of a
  client's capabilities other than from a signal on the request.

Terms not otherwise defined are used as in {{RFC6749}} and {{RFC9110}}.

# Capability Values {#values}

## Syntax {#syntax}

A capability value is a bare token. The syntax uses ABNF {{RFC5234}}, including
its `ALPHA`, `DIGIT`, and `SP` core rules:

~~~ abnf
capability        = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." / ":" )
capability-list   = capability *( SP capability )
~~~
{: title="Capability value syntax"}

This character set satisfies two constraints at once, and is narrower than
either: the value is valid as a sequence of `NQCHAR` in a form-encoded OAuth
parameter ({{Appendix A of RFC6749}}), and valid as an `sf-token` in a
structured field ({{Section 3.3.4 of RFC9651}}). That section also encourages
new fields to use Strings rather than Tokens; this specification uses Tokens so
that a value has the same form in both carriers, without quoting.

Capability values are case-sensitive. Four rules apply wherever a capability
value appears, in every carrier in {{carriers}} and in {{discovery}}:

- A value MUST conform to the `capability` production.
- Order is not significant.
- Duplicates MUST be ignored.
- A recipient MUST ignore a value it does not recognize.

What a non-conforming value causes differs by carrier, and is stated with each.

Capability values MUST NOT carry parameters. An extension that needs structured
detail alongside a capability defines a companion request parameter, or uses
`authorization_details` {{RFC9396}}. The registry is a flat vocabulary.

## Naming Guidance {#naming}

A capability value names a specific client behavior that a server may exercise
after receiving the value, not a document. `accept-deferred-response` is a
capability; `draft-ietf-oauth-deferred-token-response` is not. A
specification MAY register more than one value where a client can usefully
implement part of it.

A new revision of an extension whose client-side processing differs registers a
new value rather than reusing the old one. Registering the new value does not
retire the old one; its change controller can mark it obsolete in the registry
({{iana-registry}}). A server that recognizes several
revisions of a behavior serves clients built against each of them from a single
deployment.

Because client-side processing may change while an extension is being revised,
an extension SHOULD register a value only once the processing it names is
stable. Unregistered values are not a general substitute in the interim,
because two implementations can give one value different meanings
({{unregistered-values}}). Unregistered values therefore SHOULD be confined
to deployments whose parties have agreed on their meaning out of band, and
registration SHOULD be sought once deployment becomes interoperable. The
registry's Specification Required policy ({{iana-registry}}) allows a value to
be registered once a stable specification documents it; for an IETF-stream
specification that will be published as an RFC, early allocation {{RFC7120}}
is also available.

A revision number is a document reference, so a value SHOULD NOT carry one: it
means nothing once the draft is published, and a run of revisions with
identical client processing would imply as many variants. Where the revised
behavior can be named, name it. Where it cannot, because a format changed in
many small ways at once, a bare sequence suffix indexes variants without
pointing at a document.

The following non-normative example shows the distinction. Suppose an
extension defines a transaction authorization challenge, and a later revision
changes the challenge from a set of form-encoded parameters to a JWT, so that a
client built against the earlier revision cannot parse the later one:

- `txn-challenge` names the original behavior.
- `txn-challenge-jwt` names the revised behavior by what a client must now
  parse, and is the preferred registration.
- `txn-challenge-2` is acceptable where no behavioral name is available.
- `txn-challenge-11` is not, because the suffix names a draft revision rather
  than a behavior.

A protocol version is not a capability under any name, such as `oauth-2.1`
({{profiles}}).

## The `none` Sentinel {#none-value}

The token `none` is reserved and is never a capability. A client sends it as
the complete value of the `client_capabilities` request parameter, or as the
only member of the `OAuth-Client-Capabilities` field, to send a signal that
contains no capability. Because a request-level signal replaces any default
({{precedence}}), this retracts a statically declared set or, at a protected
resource, out-of-band knowledge.

`none` MUST NOT appear together with any capability value. It is registered
only to reserve the token ({{iana-registry}}) and enables no behavior, so a
recipient acts on it as on a value it does not recognize ({{syntax}}). Its
presence never makes a request parameter, field, client metadata, or discovery
value invalid.

# Capability Invariants {#invariants}

The following three constraints are normative and apply to every registered
capability value and to every use of the carriers in {{carriers}}.

CAP-1:
: A capability MUST only enable optional server behavior. Removing a capability
  value from the effective capability set MUST NOT cause a server to apply
  weaker client authentication, weaker sender constraining, weaker user
  authentication, or a more permissive policy than it would have applied had
  the value never been defined. Adding a capability value MUST NOT lower the
  assurance a server requires, or lead it to accept weaker client
  authentication, sender constraining, or user authentication than that
  assurance demands. Among paths that meet that assurance, a value can affect
  which one the server takes ({{selection}}). A capability MUST NOT enable a
  security check that the server would otherwise skip, including stricter
  validation of the client's own requests, because removing the value would
  remove the check. Absence MUST be safe.

CAP-2:
: A capability MUST NOT establish what a client is permitted to obtain or be
  accepted as evidence in an authorization decision. A capability describes
  what a client is able to process. Servers MUST NOT grant scope, relax consent
  requirements, or extend token lifetimes on the basis of a signaled
  capability.

CAP-3:
: A server MUST NOT rely on a capability signal being truthful. The security
  properties of the enabled behavior MUST hold even when the client does not
  implement the capability, and when a party other than the client asserts it,
  including one that relays the enabled behavior to someone else.
  A capability MUST NOT substitute for client authentication, proof of
  possession, protocol validation, or other evidence required by the behavior
  it enables.

These invariants also serve as the admission criterion for the registry; see
{{extension-guidance}}.

# Carriers {#carriers}

The kind of request decides which carrier conveys its request-level signal and
what applies when it carries none. The following table summarizes the kinds
that {{precedence}} defines:

| Request | Request-level signal | Default |
|---|---|---|
| Authorization, pushed authorization, or token request, or a request to another endpoint where an extension defines the parameter | `client_capabilities` request parameter ({{param}}) | Client metadata ({{metadata}}) |
| Protected resource request, including one to UserInfo | `OAuth-Client-Capabilities` field ({{field}}) | Out-of-band knowledge, where an extension defines it |
| Other authorization server request, such as introspection, revocation, registration, or client configuration, even when authorized with an access token | None | None: no effective set |
{: title="Carrier and default by kind of request"}

## The `client_capabilities` Request Parameter {#param}

client_capabilities:
: OPTIONAL. A space-delimited list of capability values, as defined in
  {{values}}.

The parameter is defined for use at the authorization endpoint and token
endpoint. A pushed authorization request can carry this parameter as specified
by {{RFC9126}}. The parameter MAY appear inside a Request Object {{RFC9101}}.
An extension MAY define its use at another endpoint that accepts OAuth request
parameters.

~~~ http-message
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
&client_id=https%3A%2F%2Fapp.example%2Fclient
&client_capabilities=accept-deferred-response
~~~
{: title="A capability signaled on a token request"}

The `capability-list` production ({{syntax}}) is applied to the parameter's
value after `application/x-www-form-urlencoded` decoding. An empty value is
treated as omitted, as required by {{RFC6749}}. A non-empty value that does not
match this production, including a value with leading, trailing, or repeated
spaces, is invalid. A recipient MUST treat an invalid value as signaling the
empty set and MUST NOT reject the request solely because the value is invalid,
except as permitted by {{dos}}.

When an authorization request uses a Request Object, the authorization server
uses only the parameters inside it ({{Section 6.3 of RFC9101}}). A
`client_capabilities` value outside the Request Object is not used, and if the
Request Object contains no such value, the parameter is absent for the purposes
of {{precedence}}. An authorization request that uses a `request_uri` from a
pushed authorization request is built as defined in {{RFC9101}}
({{Section 4 of RFC9126}}), so the same holds for the parameters that were
pushed: a `client_capabilities` value sent alongside the `request_uri` is not
used. Inside a Request Object, the value is a JSON string containing a
`capability-list`. An empty string is treated as omitted, as for the
form-encoded parameter, and a value of any other JSON type, including `null`,
is invalid.

The parameter is not defined for the client registration endpoint. A client
declares capabilities there using the `client_capabilities` metadata field in
{{metadata}}.

A client MAY send `client_capabilities` to any authorization server without
prior knowledge of whether the server implements this specification at the
authorization or token endpoint. Sections 3.1 and 3.2 of {{RFC6749}} require an
authorization server to ignore unrecognized request parameters at those
endpoints. Specifications that define its use at another endpoint MUST ensure
that unrecognized request parameters are ignored there. No negotiation
handshake is defined.

The parameter MUST NOT be sent with an empty value. A client that wants an
empty effective set omits the parameter when no metadata default applies and
sends `none` when it needs to override such a default.

The parameter is not repeatable: a client sends its list as one space-delimited
value. A request that includes `client_capabilities` more than once is
malformed, as Sections 3.1 and 3.2 of {{RFC6749}} provide for that
specification's own parameters, and an authorization server MUST reject it with
the `invalid_request` error code (Sections 4.1.2.1 and 5.2 of {{RFC6749}}).
This differs from an invalid value, which is not rejected.

Where the parameter would otherwise be carried in the query component of an
authorization request URI, a pushed authorization request {{RFC9126}} bounds
URI growth and keeps the list off the user agent; passing a Request Object
{{RFC9101}} by value does not reduce URI size. {{privacy-considerations}}
covers a client that considers its capability set sensitive.

## The `OAuth-Client-Capabilities` HTTP Field {#field}

The `OAuth-Client-Capabilities` HTTP field allows a client to signal
capabilities on a request that has no OAuth request parameter surface, such as
a protected resource request.

The field asserts that whatever processes the response can process the
behavior: the sender alone, or the sender together with another component on
whose behalf it acts, as when an agent making a resource request relays a
challenge to a component that completes it. Because the field does not
necessarily identify the OAuth client, client metadata supplies no default for
it ({{precedence}}).

A client MUST NOT use the field on a request to an endpoint where the
`client_capabilities` request parameter is defined: the authorization, pushed
authorization request, and token endpoints, and any endpoint where an extension
defines the parameter. It uses the request parameter there ({{param}}), and an
authorization server MUST ignore the field on any request to such an endpoint.
Using only the parameter at these endpoints gives each request one unambiguous
effective set, and allows Request Object or pushed-request protections where
those apply. The field plays no part in any other request to an authorization
server either, even one authorized with an access token, unless it is a
protected resource request as {{precedence}} defines it, such as a request to
the OpenID Connect UserInfo endpoint {{OIDC}}.

The field's value is a Structured Fields List ({{Section 3.1 of RFC9651}}). Each
member MUST be an Item whose bare item is a Token containing a capability value
as defined in {{values}}:

~~~ http-message
GET /transfers/42 HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGci...
OAuth-Client-Capabilities: txn-challenge
~~~
{: title="Signaling a capability on a protected resource request"}

Senders MUST NOT generate Inner List members, members of another bare-item
type, or parameters. A recipient MUST parse the field as a Structured Fields
List. The field is invalid if parsing fails, if any member is not a Token Item,
or if any member's Token does not conform to the `capability` production in
{{values}}. A Structured Fields Token can be well formed and still violate that
production, as `*bad` does. A recipient MUST treat an invalid field as absent.
It contributes no capabilities, and the rule in {{precedence}} for a protected
resource request without a valid field then applies, including any out-of-band
knowledge an extension defines.

A recipient MUST ignore parameters.


A server MUST list `OAuth-Client-Capabilities` in the `Vary` field, or send
`Vary: *` ({{Section 12.5.5 of RFC9110}}), on every response whose status code,
header fields, or content could have differed had the request carried, omitted,
or changed the `OAuth-Client-Capabilities` field. This includes a response to a
request that omits the field.

An empty List is treated as an absent field ({{precedence}}). Structured Fields
serializes an empty List by omitting the field ({{Section 3.1 of RFC9651}}),
and parses an empty field value as an empty List.

A browser-based client that sends the field on a cross-origin request causes a
CORS preflight, because `OAuth-Client-Capabilities` is not a CORS-safelisted
request header {{FETCH}}. A protected resource that serves such clients has to
allow the field in its preflight response, most simply by listing the field
name in `Access-Control-Allow-Headers`; a `*` value there covers the field only
when the request's credentials mode is not `include`. Otherwise the browser
does not send the request, and ignoring unrecognized values cannot help. A
resource that advertises `client_capabilities_supported` ({{discovery}}) and
serves browser-based clients therefore allows the field. A browser-based client
SHOULD NOT send the field on a cross-origin request unless it knows that the
protected resource allows the field, for example because the resource
advertises `client_capabilities_supported`.

## Client Metadata Declaration {#metadata}

client_capabilities:
: OPTIONAL. A JSON array of strings, each a capability value as defined in
  {{values}}, describing the default capabilities of the client identified by
  the metadata.

This client metadata field {{RFC7591}} covers metadata registered with an
authorization server, published at a Client Identifier URL {{CIMD}}, or carried
in a software statement. Depending on the mechanism, it can describe client
software, a deployed instance, or both; see {{precedence}}.

The array MUST NOT contain `none`. An absent field and an empty array both
denote the empty set. If the value is not an array, or any element is not a
string or does not conform to the `capability` production, the field is
invalid. A recipient MUST ignore an invalid field, deriving no
capabilities from it, and MUST NOT reject an otherwise-valid metadata document
or registration request solely because this field is invalid, except as
permitted by {{dos}}. This rule concerns only the `client_capabilities` field;
it does not change how the containing protocol handles invalid JSON, a failed
signature, or its other required validation.

A party publishing or registering this metadata MUST NOT declare a capability
unless every client instance covered by that metadata can process the enabled
behavior, or every less-capable instance will override the default on its
requests. A client whose instances differ can instead omit the field and signal
capabilities on each request, which does not depend on every less-capable
instance overriding the default.

A client metadata document published at a Client Identifier URL {{CIMD}} is
publicly retrievable, applies uniformly to every deployment using the URL, and
may be cached. Clients identified this way SHOULD treat the request parameter
in {{param}} as the primary carrier.

## Determining the Effective Capability Set {#precedence}

The effective capability set depends on the kind of request:

OAuth request:
: A request to the authorization, pushed authorization request, or token
  endpoint, or to another endpoint where an extension defines the request
  parameter. Its request-level signal is the `client_capabilities` parameter
  ({{param}}), and its default is client metadata ({{metadata}}).

Protected resource request:
: A request with which a client accesses data that a protected resource serves,
  including a resource that an authorization server hosts, such as UserInfo.
  Its request-level signal is the `OAuth-Client-Capabilities` field
  ({{field}}), and its default is any out-of-band knowledge an extension
  defines.

Other authorization server requests:
: Requests to any other authorization server endpoint, at which a client or
  another party performs an OAuth operation, such as obtaining, inspecting, or
  revoking a grant or token, or managing a registration. Examples are the
  introspection {{RFC7662}}, revocation {{RFC7009}}, device authorization
  {{RFC8628}}, client registration {{RFC7591}}, and client configuration
  {{RFC7592}} endpoints. A request to such an endpoint is of this kind even when
  it is authorized with an access token, and even if the endpoint's own
  specification calls it a protected resource. These requests have no effective
  set. At the client registration and client configuration
  endpoints, a client declares capabilities in client metadata instead
  ({{metadata}}). An extension that needs a capability at another such endpoint
  defines the request parameter there, which makes requests to it OAuth
  requests.

For an OAuth request or a protected resource request, the effective capability
set is determined as follows:

1. If the request carries its request-level signal, the signal's value is the
   effective set. A request parameter that is invalid ({{param}}) or exceeds a
   limit ({{dos}}) is still present, and the effective set is then empty. A
   field counts only if it is valid and has at least one member, even if the
   server recognizes no value in it; an absent field, an empty List, and an
   invalid field are treated alike, as no signal.
2. Otherwise, the default is the effective set. For an OAuth request, it is the
   `client_capabilities` value from the client metadata that the authorization
   server considers authoritative for the client making the request. Client
   metadata is never the default for a protected resource request.
3. If neither is present, the effective set is empty.

A request-level signal replaces the default rather than augmenting it, so that
a less-capable instance can retract a default. To retract everything, a client
sends `none` ({{none-value}}).

A capability set in a software statement is client metadata and remains subject
to the request-level override above; signing the statement does not turn a
default into a per-request declaration.

## Scope of a Signal {#signal-scope}

A request-level signal applies only to that request, not to later requests in
the grant. Client metadata supplies a default for each request as described in
{{precedence}}; it does not make a prior request-level signal persist. A server
MUST NOT promote a request-level capability set to durable client metadata or
to out-of-band knowledge.

A capability in a pushed authorization request applies to the authorization
request represented by the resulting `request_uri`, and nothing else. A
capability governing token endpoint behavior MUST be in the effective set for
the token request that elicits the behavior; the authorization server MUST NOT
infer it from an earlier request in the grant. Each request in a sequence that
an extension defines, such as a poll after a deferred response or a retry after
a challenge, has its own effective set. The extension states whether a
follow-on request has to carry the value or continues the behavior that the
originating request elicited ({{extension-guidance}}).

# Server Behavior {#server-behavior}

A server MUST NOT reject a request solely because a capability value is
unrecognized. This does not prevent an extension from refusing a request when
the effective capability set provides no usable processing path
({{selection}}), or a server from rejecting an oversized signal ({{dos}}) or a
repeated request parameter ({{param}}).

Neither signaling a capability nor advertising it ({{discovery}}) entitles a
client to the corresponding behavior. A server retains discretion over whether
to exercise optional behavior.

This specification does not define an error for an absent capability and does
not give any capability mandatory-to-understand semantics; see {{no-require}}.
An extension MAY define an error for a case in which the server cannot proceed
without a particular client-side behavior. Such an error reports the
extension's condition; it does not turn the signal into an authorization input.

## Selecting Among Alternatives {#selection}

A server may have several ways to obtain what a request lacks. For example, a
protected resource might return a transaction authorization challenge, request
step-up authentication, or refuse. The effective capability set can help it
choose a path the client asserts it can complete.

A server MUST determine the assurance a request requires without reference to
the capability set. It MAY use the set to choose among paths that meet that
requirement. If no such path is available, it MUST refuse the request. Without
this rule, removing a value could steer the server to a weaker path,
reintroducing the downgrade CAP-1 prevents. {{extension-guidance}} states when
such a choice justifies a capability value.

# Discovery {#discovery}

client_capabilities_supported:
: OPTIONAL. A JSON array of strings containing the capability values that the
  server recognizes and may act upon.

This metadata member is defined for authorization server metadata {{RFC8414}}
and for protected resource metadata {{RFC9728}}.

The array MUST NOT contain `none`. If the value is not an array, or any element
is not a string or does not conform to the `capability` production, the value
of this member is invalid and MUST be ignored in its entirety.

A client that holds a server's `client_capabilities_supported` SHOULD include
in a request-level signal to that server only values that appear in it. This
does not apply to `none` ({{none-value}}),
which a server does not list: if filtering leaves no value and the client
needs to override a metadata default or out-of-band knowledge, it sends `none`.
A client that does not hold the list MAY signal values without retrieving it
first, except as {{field}} limits for browser-based clients; a server that does
not recognize a value ignores it. Advertising
recognized values lets a client that holds the list bound request size and
fingerprinting exposure, following the pattern of Client Hints {{RFC8942}}.

Absence of `client_capabilities_supported` does not indicate that the server
fails to support this specification.

# Guidance for Extension Specifications {#extension-guidance}

An extension that needs a client to signal a processing capability SHOULD
register a value in the registry established in {{iana-registry}} rather than
define a dedicated request parameter, HTTP field, or client metadata field.

The invariants in {{invariants}} are the admission criterion. A value may be
justified on either of two grounds: that a server cannot safely exercise the
behavior without it, or that a server choosing among several paths would
otherwise select one the client cannot complete ({{selection}}). The second
requires that the signal can change whether the operation completes, not merely
make an already-workable path more convenient.

One heuristic identifies most misclassifications:

> If an implementer would want the value to be attested, it is not a
> capability.

A property that must be trustworthy to be useful is an assurance, and belongs
in client attestation {{ABCA}}, a software statement {{RFC7591}}, or an
equivalent signed structure. A capability is an assertion, not an assurance; an
extension that needs to bind it to a key or trust it in a policy decision has
misclassified it.

Additional points of discipline:

- Register a behavior, not a specification. See {{naming}}.
- Prefer server-side discovery where it works. If the client-side behavior can
  be specified as a requirement conditioned on something the server advertises
  in its own metadata ({{RFC8414}} or {{RFC9728}}), specify it that way and
  register no capability. A capability is for behavior that cannot be made
  mandatory because the server cannot learn whether the client implements it.
- State, in the registration, the carriers and endpoints at which the value is
  meaningful, and which follow-on requests, such as polls or retries, carry it
  ({{signal-scope}}).
- If the extension defines out-of-band knowledge, state how a client learns
  that it applies, so that the client knows when to send `none`.

Because capability signals may be removed by an adversary, an extension MUST
define a safe absent-signal fallback. If the enabled behavior is how a server
obtains something it requires, the fallback is refusal, not proceeding without
it. An extension that cannot describe a fallback at least as conservative as
the pre-extension behavior has not satisfied CAP-1, whatever the value is
named. The registration records the fallback ({{iana-registry}}).

Acting on a falsely asserted capability can consume server, downstream, and
human resources, such as pending state, approval prompts, and notifications to
users ({{dos}}). An extension specification MUST analyze this cost and define
any necessary rate-limiting, state-allocation, or replay protections, such as
limits on outstanding state per client and per grant.

A capability set contributes to fingerprinting ({{privacy-considerations}}).
Specifications defining capabilities whose availability depends on the
deployment environment MUST assess whether signaling them creates a useful
fingerprint and SHOULD choose names that describe behavior without exposing
implementation details.

Issuer-wide behavior is often the intended design, and coupling it to a
per-issuer metadata flag is a legitimate choice. Where per-client or fractional
rollout of a behavior that meets {{invariants}} is a requirement, however, an
extension SHOULD NOT couple the behavior to such a flag, because it then
becomes all-or-nothing for every client of the issuer; gate it on a capability
instead. {{RFC9207}} illustrates the trade-off: coupling the advertisement to a
server-wide delivery commitment allows a client to enforce that `iss` is
present, but the feature cannot be rolled out per client. A capability could
not carry that commitment; see the next paragraph.

This specification provides no delivery guarantee, and an extension MUST NOT
rely on a capability signal or on `client_capabilities_supported` to supply
one; {{server-behavior}} leaves delivery to the server. An extension that needs
a delivery commitment defines it itself, along with how a client learns the
server will honor it.

# Security Considerations {#security-considerations}

For general OAuth security considerations, see {{Section 10 of RFC6749}} and
{{RFC9700}}. The security properties of capability signaling rest on
{{invariants}}.

## Unverified Signals {#unverified-signals}

A capability signal asserts, but does not prove, that the client implements the
capability. Depending on their use, transport security, client authentication,
a Request Object, or a signed software statement can authenticate or protect
the assertion without proving it true.

On the front channel, the user agent or another intermediary can modify a bare
request parameter. Injection can produce a response the client cannot process;
removal can deny optional functionality. Under CAP-1 through CAP-3, neither may
weaken security, grant authorization, or skip evidence required by the enabled
behavior.

A signal is not an access control. Any party that can send a request, including
one holding a stolen authorization code, refresh token, or access token, can
assert a value, elicit the enabled behavior, and choose among the paths
{{selection}} permits. Each enabled behavior and each selectable path therefore
has to be safe when such a party chooses it while holding only the credentials
the request carries, including a challenge that party could relay to another
user. CAP-3 requires this, and an extension's security analysis states how its
behavior meets it.

Servers MUST NOT treat a capability signal as evidence of client identity,
client software version, or client trustworthiness. Where a Request Object
{{RFC9101}} or software statement carries a set, the signature prevents
third-party modification but does not prove implementation. See {{param}} and
{{precedence}}.

## Downgrade {#downgrade}

Because capability signals may be removed by an adversary, each extension
defines a safe absent-signal fallback ({{extension-guidance}}). With such a
fallback, removal costs client functionality, never a server security property.
Removing a signal that narrows a set widens it instead:
stripping a request parameter that overrides a metadata default restores the
default, and stripping a field that replaces out-of-band knowledge restores
that knowledge. Either can lead a server to exercise a behavior the instance
cannot process, which is a failed exchange, not a weakened one. Corrupting a
field so that it is invalid has the same effect as stripping it. Injecting
`none` removes out-of-band knowledge, which is the safe direction. On the front
channel, a signed Request Object or a pushed authorization request protects the
integrity of the override it carries, but an attacker can still substitute an
unprotected request unless the authorization server enforces its use:
`require_signed_request_object` ({{Section 10.5 of RFC9101}}) for Request
Objects, and `require_pushed_authorization_requests` ({{Section 5 of RFC9126}})
or equivalent policy for pushed requests.

A security check that CAP-1 bars a capability from enabling belongs in policy or
an authenticated negotiation mechanism.

## Denial of Service {#dos}

A capability list is attacker-controllable in size. Servers MUST apply finite
limits to the encoded length, number of members, and resources consumed while
parsing a signal. Those limits MUST admit any otherwise-valid signal of at most
4096 octets and at most 64 members, counting members before duplicates or
unrecognized values are removed; a recipient MAY accept larger signals. The
octets counted are those of the carrier's value, excluding its name and the
surrounding message:

| Carrier | Octets counted |
|---|---|
| Request parameter | The form-encoded value, before percent-decoding |
| Request parameter in a Request Object | The JSON string as serialized in the decoded JWT Claims Set, including its quotes and escapes |
| HTTP field | The combined field value, including separators and parameters |
| Client metadata | The serialized JSON array, including brackets, quotes, whitespace, and escapes |
{: title="Octets counted toward a limit"}

Decoding never lengthens a value, so a recipient that measures decoded octets
admits at least every signal that this floor requires it to admit; it still
applies a finite limit to the encoded length.


A signal that exceeds a limit MUST be treated as invalid: a request parameter
then signals the empty set ({{param}}), a field is treated as absent
({{field}}), and a client metadata field is ignored ({{metadata}}). A server
MAY instead reject the request that carries the signal, or a registration
request whose metadata carries it, using an error response appropriate to the
endpoint or application protocol. In particular, `invalid_request` is available
at OAuth endpoints and `invalid_client_metadata` at a registration endpoint
{{RFC7591}}, while a protected resource can use an application-specific
response. This does not extend to a metadata document published at a Client
Identifier URL {{CIMD}}: an otherwise acceptable document whose
`client_capabilities` field exceeds a limit is accepted with the field ignored,
as {{metadata}} requires. Rejecting such a document would be a terminal
discovery failure ({{Section 6.1 of CIMD}}), failing the client's requests
until the document changes, and may leave the client without an actionable
diagnostic, particularly at the authorization endpoint. Limits on the whole
document, such as the maximum response size in {{Section 10.11 of CIMD}}, still
apply, even when the field accounts for most of its size; a client publishing
its metadata this way keeps the field well within them.

Acting on a falsely asserted capability can also consume server, downstream,
and human resources; each extension analyzes this cost ({{extension-guidance}}).
A capability signal
does not authorize the client to consume unbounded work.

## Unregistered Values {#unregistered-values}

Two implementations can recognize the same unregistered value with different
meanings. Ignoring unrecognized values does not help, because each recognizes
the value, and authenticating the signal does not resolve a disagreement about
its meaning. A server can then exercise a behavior the client cannot process,
or spend resources on a behavior the client will not complete. Provided each
implementation meets CAP-1 through CAP-3 on its own, the result is a failed
exchange or wasted work, not weakened security. {{naming}} recommends confining
unregistered values to deployments whose parties have agreed on their meaning,
and seeking registration once deployment becomes interoperable.

# Privacy Considerations {#privacy-considerations}

A capability set discriminates over the client population and contributes to
fingerprinting. On the front channel it is visible to the user agent, and in a
publicly retrievable client metadata document it is visible to anyone. The
marginal disclosure to an authorization server is smaller, since it already
receives a `client_id` that often identifies the software, but a capability set
can still add information. A set that changes during a staged rollout
({{staged-rollout}}) can also identify a release or rollout cohort.

Clients that consider their capability set sensitive SHOULD use {{RFC9126}} or
an encrypted Request Object as defined in {{RFC9101}}, SHOULD, when they hold
the server's `client_capabilities_supported`, restrict request-level signals to
values it lists, and SHOULD NOT publish the set in public client metadata. A
signed
but unencrypted Request Object provides integrity, not confidentiality.

Capability values MUST NOT encode information about an end user or a specific
device. Extensions assess the fingerprinting effect of capabilities whose
availability depends on the deployment environment ({{extension-guidance}}).

# IANA Considerations {#iana}

## OAuth Client Capabilities Registry {#iana-registry}

This specification requests that IANA establish an "OAuth Client Capabilities"
registry in the "OAuth Parameters" registry group. Values are registered on a
Specification Required basis as defined in {{Section 4.6 of RFC8126}}.

The registry contains the following fields:

Capability Value:
: The token, conforming to the `capability` production in {{values}}.

Description:
: A brief description of the client behavior signaled by the value.

Status:
: Either `current` or `obsolete`. A value is registered as `current`. Its
  change controller MAY later set it to `obsolete` to record that a superseding
  value exists; an obsolete value remains registered, and a server MAY continue
  to recognize it.

Absent-Signal Behavior:
: What the server does when the value is not in the effective set. Recording
  this makes CAP-1 in {{invariants}} checkable at registration time.

Carriers:
: The carriers in which the value is meaningful: any of "request parameter",
  "HTTP field", "client metadata".

Endpoints:
: The endpoints or request types at which the value is meaningful, where
  applicable.

Change Controller:
: For values defined in IETF stream documents, the IETF. Otherwise, the party
  responsible for the registration.

Specification Document(s):
: A reference to the document defining the value.

Designated experts evaluating a registration request should:

- confirm that the value satisfies CAP-1 through CAP-3 in {{invariants}} and the
  criterion in {{extension-guidance}}, that the specification meets the
  requirements this document places on extensions, including those in
  {{param}}, {{selection}}, and {{extension-guidance}}, and that its registered
  absent-signal behavior is at least as conservative as what the server would
  apply had the value never been defined;
- confirm that the specification defines the optional behavior enabled and
  identifies every applicable carrier and endpoint;
- confirm that the value encodes no information about an end user or a specific
  device ({{privacy-considerations}});
- consider the security, privacy, interoperability, and operational effects of
  false assertion and signal removal; and
- reject values that duplicate the semantics of an existing registration, differ
  from one only in letter case, or name a document revision rather than a
  behavior.

The designated experts should presume that a registration is acceptable when
these requirements are met. They may obtain feedback from the OAuth Working
Group or its successor, but working group consensus is not required.

The registry's initial content is:

Capability Value:
: `none`

Description:
: Reserved. Never a capability; sent alone, it signals no capability.

Status:
: current

Absent-Signal Behavior:
: Not applicable. `none` is reserved and is never a capability.

Carriers:
: request parameter, HTTP field

Endpoints:
: Any authorization server endpoint at which the request parameter is defined,
  and any protected resource

Change Controller:
: IETF

Specification Document(s):
: This specification, {{none-value}}

## OAuth Parameters Registry {#iana-params}

This specification requests registration of the following value in the IANA
"OAuth Parameters" registry established by {{RFC6749}}:

Parameter Name:
: `client_capabilities`

Parameter Usage Location:
: authorization request, token request

Change Controller:
: IETF

Specification Document(s):
: This specification, {{param}}

## OAuth Dynamic Client Registration Metadata Registry {#iana-dcr}

This specification requests registration of the following value in the IANA
"OAuth Dynamic Client Registration Metadata" registry established by
{{RFC7591}}:

Client Metadata Name:
: `client_capabilities`

Client Metadata Description:
: JSON array of default capability values describing behaviors the client is
  able to process

Change Controller:
: IETF

Specification Document(s):
: This specification, {{metadata}}

## OAuth Authorization Server Metadata Registry {#iana-as-metadata}

This specification requests registration of the following value in the IANA
"OAuth Authorization Server Metadata" registry established by {{RFC8414}}:

Metadata Name:
: `client_capabilities_supported`

Metadata Description:
: JSON array of capability values the authorization server recognizes and may
  act upon

Change Controller:
: IETF

Specification Document(s):
: This specification, {{discovery}}

## OAuth Protected Resource Metadata Registry {#iana-pr-metadata}

This specification requests registration of the following value in the IANA
"OAuth Protected Resource Metadata" registry established by {{RFC9728}}:

Metadata Name:
: `client_capabilities_supported`

Metadata Description:
: JSON array of capability values the protected resource recognizes and may act
  upon

Change Controller:
: IETF

Specification Document(s):
: This specification, {{discovery}}

## HTTP Field Name Registry {#iana-field}

This specification requests registration of the following value in the
"Hypertext Transfer Protocol (HTTP) Field Name" registry:

Field Name:
: `OAuth-Client-Capabilities`

Status:
: permanent

Structured Type:
: List

Reference:
: This specification, {{field}}

--- back

# Examples {#examples}

This specification registers no capability values. The
`accept-deferred-response` and `txn-challenge` values below are illustrative,
corresponding to behaviors described in {{existing-drafts}}. Line breaks in
the form-encoded request bodies are for display only.

## Worked Adoption {#worked-adoption}

This example follows one adoption of the deferred-response behavior in
{{existing-drafts}}, from discovery to a default declared in client metadata.
The deferred response and the behavior when the value is absent are those
{{DTR}} defines; this specification changes only how the client signals that it
can process the response. No request before the token request carries the
value, so no pre-token hint ({{existing-drafts}}) applies.

The authorization server advertises the value in its metadata {{RFC8414}}
({{discovery}}):

~~~ json
{
  "issuer": "https://as.example.com",
  "token_endpoint": "https://as.example.com/token",
  "client_capabilities_supported": ["accept-deferred-response"]
}
~~~
{: title="Authorization server metadata excerpt"}

A client release that can process a deferred response signals the value on its
token request. The client is public, so the request also carries a DPoP proof
{{RFC9449}}, which Section 11.1 of {{DTR}} requires on a token request that
yields a deferred response:

~~~ http-message
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7...

grant_type=authorization_code&code=SplxlOB...
&client_id=https%3A%2F%2Fapp.example%2Fclient
&redirect_uri=https%3A%2F%2Fapp.example%2Fcb
&code_verifier=dBjftJeZ...
&client_capabilities=accept-deferred-response
~~~
{: title="Signaling at the endpoint where the behavior occurs"}

The authorization server elects to defer and, in place of a token response,
returns the deferred response defined in Section 6.4 of {{DTR}}:

~~~ http-message
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{
  "error": "authorization_pending",
  "deferral_code": "TfZUlGEqTJeW7oNlcxnXs2kECOk",
  "expires_in": 10800,
  "interval": 60
}
~~~
{: title="Deferred response to a request that signals the capability"}

The client then polls as {{DTR}} describes. Each poll carries a DPoP proof
signed by the key that signed the token request's proof, and the access token
eventually issued is bound to that key. The polls continue the deferral that
the original request elicited; a registration of the value states whether they
also carry it ({{signal-scope}}).

A token request whose effective set does not contain the value never elicits a
deferral: the authorization server completes it synchronously, or returns an
error under the grant's rules (Section 5.3 of {{DTR}}), which is
`invalid_request` after a pre-token hint ({{existing-drafts}}). Omitting the
value rules out deferral, not failure. The following response to the same token
request without the value assumes that the authorization server can complete
every check it requires without deferral:

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{
  "access_token": "2YotnFZFEjr1zCsicMWpAA",
  "token_type": "DPoP",
  "expires_in": 3600
}
~~~
{: title="Synchronous response when the value is absent"}

A registered client can instead declare the value as a default in its client
metadata. Every instance covered by the registration can process the behavior
or overrides the default on its requests ({{metadata}}):

~~~ http-message
POST /register HTTP/1.1
Host: as.example.com
Content-Type: application/json

{
  "redirect_uris": ["https://app.example/cb"],
  "token_endpoint_auth_method": "none",
  "client_capabilities": ["accept-deferred-response"]
}
~~~
{: title="Default capability set in a registration request"}

The registered client's token requests then carry no `client_capabilities`
parameter and receive the default ({{precedence}}), so the authorization server
may defer them, and they carry DPoP proofs for the same reason. An instance
that cannot process a deferred response overrides the default with `none` on
its requests:

~~~ http-message
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=SplxlOB...
&client_id=s6BhdRkqt3
&redirect_uri=https%3A%2F%2Fapp.example%2Fcb
&code_verifier=dBjftJeZ...
&client_capabilities=none
~~~
{: title="Explicit retraction by a less-capable instance"}

Its token requests are then never deferred: each receives a token response or
an error.

## Staged Rollout {#staged-rollout}

A client identified by a published metadata document {{CIMD}} can stage
optional behavior without changing the document. Suppose an updated release can
accept a deferred token response ({{worked-adoption}}). The document continues
to declare only what every instance can process. The updated release sends its
complete set, including the illustrative `accept-deferred-response`, to one
authorization server, since a request-level signal replaces the metadata
default rather than adding to it ({{precedence}}). It sends other authorization
servers nothing new, and older releases are unaffected. While the document does
not declare the value, the release enables or stops it per request and per
authorization server. Once the document declares it, an instance withdraws it
only by sending a set without it, or `none`. In both cases one document serves
every authorization server.

This works only for optional behavior. A metadata field that requires a
behavior applies at every authorization server that supports it: once
`dpop_bound_access_tokens` is true, such a server rejects token requests
without DPoP {{RFC9449}}. Such a field cannot be a capability ({{invariants}}),
and staging a change to it remains a problem for client metadata itself.

## Pushed Authorization Request {#example-par}

A pushed authorization request carries the parameter in its body, which keeps
the value off the authorization URI. The value applies only to the
authorization request that the resulting `request_uri` represents
({{signal-scope}}), where, under the adoption in {{existing-drafts}}, it would
be a pre-token hint:

~~~ http-message
POST /par HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

response_type=code&client_id=https%3A%2F%2Fapp.example%2Fclient
&redirect_uri=https%3A%2F%2Fapp.example%2Fcb
&code_challenge=W6uP...&code_challenge_method=S256
&client_capabilities=accept-deferred-response
~~~
{: title="Capability carried in a pushed authorization request"}

## Request Object {#example-request-object}

In the claims of a Request Object, the value is a JSON string, not an array
({{param}}):

~~~ json
{
  "iss": "https://app.example/client",
  "aud": "https://as.example.com",
  "response_type": "code",
  "client_id": "https://app.example/client",
  "redirect_uri": "https://app.example/cb",
  "code_challenge": "W6uP...",
  "code_challenge_method": "S256",
  "client_capabilities": "accept-deferred-response"
}
~~~
{: title="Capability carried in Request Object claims"}

## Protected Resource Metadata {#example-pr-metadata}

A protected resource advertises the values it recognizes in its metadata
{{RFC9728}} ({{discovery}}):

~~~ json
{
  "resource": "https://api.example.com",
  "authorization_servers": ["https://as.example.com"],
  "client_capabilities_supported": ["txn-challenge"]
}
~~~
{: title="Protected resource metadata excerpt"}

## Illustrative Registry Entry {#example-registration}

The following is an illustrative entry for the deferred-response behavior in
{{existing-drafts}}, filled in as {{iana-registry}} describes. It is not a
registration request.

Capability Value:
: `accept-deferred-response`

Description:
: The client can process a deferred token response.

Status:
: current

Absent-Signal Behavior:
: The authorization server does not defer. It responds synchronously only if
  it can complete every check it requires without deferral, and otherwise
  returns an error. If an earlier request in the grant carried the value as a
  pre-token hint, it instead rejects the token request with `invalid_request`
  ({{existing-drafts}}).

Carriers:
: request parameter, client metadata

Endpoints:
: token endpoint, on a request that can be deferred but not on polls; and, as
  a pre-token hint carried only in the request parameter, any endpoint whose
  request precedes the token request in the grant, such as the authorization
  or pushed authorization request endpoint ({{existing-drafts}})

Change Controller:
: The party responsible for the registration

Specification Document(s):
: {{DTR}}

# Applying This Specification to Existing Drafts {#existing-drafts}

This appendix is informative and describes how the two extensions that
motivated this work would use the mechanism.

Deferred Token Response:
: `completion_mode=deferred` becomes `client_capabilities` containing
  `accept-deferred-response`, and `deferred_interactive` would become a second
  value that a client sends together with it. The authorization server still
  defers only when `accept-deferred-response` is in the token request's
  effective set ({{signal-scope}}). The pre-token hint of {{DTR}} becomes the
  value in the preceding request's effective set when that set comes from its
  `client_capabilities` parameter ({{precedence}}). A metadata default is not
  a hint: the client did not send it, and counting it would subject a
  less-capable instance that redeems the code to the consistency rule below for
  a hint it never made. Where that request goes to an
  endpoint other than the authorization or pushed authorization request
  endpoint, such as the device authorization endpoint, {{DTR}} would define the
  request parameter there ({{param}}). The authorization server can act on a
  hint for the originating grant as Section 5.2 of {{DTR}} describes, provided
  the assurance the grant requires is decided without the hint ({{selection}})
  and no consent requirement is relaxed (CAP-2). The rule in Section 5.2 of
  {{DTR}} that a token request omitting `deferred` after a hint is rejected
  with `invalid_request` carries over, whether or not the server acted on the
  hint: a token request whose effective set lacks the value after a hint,
  including one that sends `none`, is rejected. That is an error the extension
  defines ({{server-behavior}}), and a consequence of the earlier request rather
  than a capability carried forward: the token request is deferred only if its
  own effective set contains the value ({{signal-scope}}). Nor is it a security
  check, which CAP-1 bars. If the hint is stripped, the check goes with it, but
  the token request is still handled under its own effective set and the
  absent-signal behavior, so no protection is lost. Retracting the value at the
  token endpoint rules out deferral but does not guarantee success. The
  proposed
  single-purpose registry is subsumed by {{iana-registry}}, and the
  `deferred_token_response_supported` authorization server metadata Boolean
  by `client_capabilities_supported` containing the value. Either suffices to
  show that a server recognizes the capability, and a disagreement between
  them affects only which values a client chooses to send ({{discovery}}).

Transaction Authorization Challenge:
: `Accept-Txn-Challenge: ?1` becomes
  `OAuth-Client-Capabilities: txn-challenge`. The Boolean becomes membership
  of `txn-challenge` in the request's effective set ({{precedence}}).
  Out-of-band knowledge of support applies only when the request carries no
  valid field with at least one member.

# Design Rationale {#rationale}

This appendix is informative.

## Survey of Existing Mechanisms {#survey}

OAuth has static client declarations {{RFC7591}}, extensible server metadata
{{RFC8414}} {{RFC9728}}, and per-extension request parameters, HTTP fields, or
signals implied by construction, such as a DPoP proof {{RFC9449}}. Static
metadata cannot express per-request or per-instance variation, while server
metadata runs only server to client.

Capabilities also differ from existing constructs. `scope` is an
authorization construct: its values are consented to, are often displayed to a
user, and are carried in the resulting grant and access token, while
capabilities are not consented to, not displayed, and by CAP-2 barred from
affecting the grant. `grant_types` and `response_types` select protocol flows
and constrain which requests a registered client may make, so their absence can
cause a request to fail; a capability describes optional response processing
and has the safe-absence property in CAP-1. Client attestation {{ABCA}}
addresses what can be proven about the client rather than what it can do
({{extension-guidance}}).

Other protocols use shared vocabularies. SIP option tags {{RFC3261}} pair
`Supported` with `Require`; HTTP `Prefer` {{RFC7240}} registers preferences
such as `respond-async`; and Client Hints {{RFC8942}} lets a server advertise
what it wants sent. GNAP {{RFC9635}} has generic, registry-backed
server-to-client discovery and anticipates "any additional capabilities
defined by extensions of this protocol", but represents client-to-server
capabilities per feature.

The IANA "OAuth Parameters" registry group currently contains no generic client
capability parameter, field, or registry {{IANA-OAUTH}}.

## Comparison with HTTP Prefer {#why-not-prefer}

`Prefer` {{RFC7240}} is the closest existing mechanism. A server may ignore a
preference, as it may decline to exercise a capability, and `respond-async`
lets a client indicate "its capability and preference for handling asynchronous
responses" ({{Section 4.1 of RFC7240}}). A registered preference could carry
each behavior in {{existing-drafts}} on direct HTTP requests, such as token
requests and protected resource requests.

`Prefer` does not serve the rest of OAuth's topology, which is why a request
parameter is needed in any case. As an HTTP field, it cannot cross the redirect
at the authorization endpoint ({{asymmetry}}), cannot be carried in a Request
Object, does not travel with the authorization request that a pushed
authorization request represents, and has no client metadata form to supply
defaults ({{metadata}}).

For the HTTP carrier alone, a single registered preference listing capability
values, such as `Prefer: oauth-client-capabilities="txn-challenge"`, could
draw on the registry in {{iana-registry}} and its admission criterion. A
server whose application of a preference affects caching must, however, list
`Prefer` in `Vary` whether or not the request carried it
({{Section 2 of RFC7240}}), so caches would key on every preference a client
sends rather than only on its capabilities. The list would also be a quoted
string parsed by the `capability-list` rule in {{values}}, not a Structured
Fields List with its own parser and error handling ({{field}}). Whether such a
preference should replace the dedicated field is an open issue
({{open-issues}}).

## Applying the Admission Criterion {#admission}

The behaviors in {{existing-drafts}} qualify if their registrations state the
safe fallback: a synchronous response or error for deferred response, and
refusal without the optional transaction challenge. Signal removal suppresses
optional behavior without weakening a security check.

Similar-looking behaviors do not necessarily qualify. A signal cannot gate DPoP
nonce enforcement {{RFC9449}}, because removing it would weaken replay
protection, and CAP-2 prevents using it to justify longer-lived tokens.
Offering the `use_dpop_nonce` challenge is a different question: where server
policy already requires a nonce and the absent-signal behavior is refusal, the
choice between challenging and refusing is a selection ({{selection}}) and
could qualify. Whether it warrants a value is a separate matter, since
{{Section 8.2 of RFC9449}} already requires a client to use a nonce supplied in
a successful token response.

The `redirect_to_web` fallback in {{FIRST-PARTY-APPS}} qualifies only if
defined as optional server behavior with a safe absent-signal outcome. If
server metadata can instead make the client behavior conditional, discovery is
preferable.

Adding a parameter to a response is almost never a capability. Sections
4.1.2 and 5.1 of {{RFC6749}} already require clients to ignore unrecognized
authorization response parameters and unrecognized token response members, so
delivery is safe for any conforming client and needs no gate.
{{RESOURCE-TOKEN-RESP}} is a case of this kind: it returns a `resource`
parameter so a client can confirm which resource its token is valid for, and
what it needs is a way for clients to learn that a server implements it. That
is server metadata, not a client capability.

On gating grounds the criterion also rejects client authentication methods,
endpoint selection, client-initiated parameters, and behavior a specification
makes mandatory to implement.

Path selection is the one exception. A behavior safe to issue unconditionally
needs no gating signal, yet can still qualify where a server must choose among
paths and the signal prevents it selecting one the client cannot complete;
{{selection}} governs that case and {{extension-guidance}} bounds it.

## Absence of Mandatory-to-Understand Semantics {#no-require}

SIP {{RFC3261}} pairs `Supported` with `Require`, letting a client insist an
extension be understood or the request fail. This specification omits the
analogue: `Require` answers a different question, whether the client insists
the server implement something, while a capability states that the client can
process behavior the server remains free not to exercise. Extensions needing
hard failure define their own errors; CAP-1 still prevents removal from
weakening security.

## Capabilities and Profile Selection {#profiles}

Selecting a protocol version or profile, such as OAuth 2.0 or OAuth 2.1 rules
for a client {{OAUTH21-VERSIONS}}, is outside this mechanism. A version changes
the authorization server's request-processing policy, not what a client must
process in a response, and a signal that enables a check is what CAP-1
excludes. OAuth 2.1 leaves the choice to the authorization server's
configuration for each client and defines no version signal
({{Section 1.8 of OAUTH21}}).

A revision that changes what a client must process in a response is different:
it is a client-side behavior, and {{naming}} gives it a new capability value.

A removable version selector, sent on each request so that updated releases can
opt in, cannot establish a security minimum for the client while requests
without it are still accepted, because an attacker sending a request under the
same `client_id` omits it. Protections a server attaches to credentials issued
under such a selector, such as rotation of a refresh token family
({{Section 4.3.1 of OAUTH21}}), can persist after a later omission. Whether to
define such a selector belongs to the OAuth 2.1 work.

## Trade-offs {#tradeoffs}

Cache keys become coarser. A protected resource whose responses vary by
capability sends `Vary: OAuth-Client-Capabilities`, keying the cache on the
whole list. Per-feature fields are more precise, though protected responses are
typically not shared-cacheable.

Coordination replaces autonomy. Registering a dedicated parameter requires no
shared vocabulary; this registry requires naming discipline and agreement on
CAP-1 through CAP-3.

A request-level signal replaces the metadata default rather than adding to it
({{precedence}}). A client that adds one value on a request repeats every
default it still wants; in exchange, a less-capable instance can retract a
default without a per-value removal syntax.

The current extension count is small. The registry anticipates continued growth
and is easier to establish before more incompatible carriers ship.

## Open Issues {#open-issues}

- Should a server report which capabilities it acted upon, as {{RFC7240}} does
  with `Preference-Applied`? The current answer is no because the response
  reveals the behavior; implementation experience might show a debugging need.
- `OAuth-Client-Capabilities` matches the naming of `OAuth-Client-Attestation`
  {{ABCA}}. `Accept-OAuth-Capabilities` would match the `Accept-*` family. The
  former is preferred because the field declares client behavior rather than
  negotiating content, but the choice is not settled.
- Whether the HTTP carrier should be a single registered `Prefer` preference
  rather than a dedicated field ({{why-not-prefer}}).
- Whether the `.` and `:` characters the syntax allows should carry any
  structure. No structure is needed today: a revision with different
  client-side processing registers a new value ({{naming}}).
- Whether client software capabilities and running instance capabilities are
  adequately separated by the replacement rule in {{precedence}}, or whether
  instance-level identity mechanisms should carry a capability set of their
  own.

# Acknowledgments
{:numbered="false"}

This work was motivated by {{DTR}} and {{TXN-CHALLENGE}}, whose authors
independently identified the same requirement and whose divergent solutions
made the general problem visible.
