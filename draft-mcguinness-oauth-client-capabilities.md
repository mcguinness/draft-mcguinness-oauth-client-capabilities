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
  RFC7662:
  RFC8628:
  RFC8942:
  RFC9396:
  RFC9449:
  RFC9635:
  RFC9700:
  RESOURCE-TOKEN-RESP:
    target: https://datatracker.ietf.org/doc/draft-mcguinness-oauth-resource-token-resp
    title: "Resource Token Response Parameter"
  OAUTH21-VERSIONS:
    target: https://github.com/oauth-wg/oauth-v2-1/issues/120
    title: "How can an AS support both 2.0 and 2.1 clients concurrently"
  OAUTH21: I-D.ietf-oauth-v2-1
  DTR:
    target: https://datatracker.ietf.org/doc/draft-gerber-oauth-deferred-token-response
    title: "Deferred Token Response"
  TXN-CHALLENGE:
    target: https://datatracker.ietf.org/doc/draft-rosomakho-oauth-txn-challenge
    title: "Transaction Authorization Challenge"
  CIMD:
    target: https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document
    title: "OAuth Client ID Metadata Document"
  FIRST-PARTY-APPS:
    target: https://datatracker.ietf.org/doc/draft-ietf-oauth-first-party-apps
    title: "OAuth 2.0 for First-Party Applications"
  ABCA:
    target: https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth
    title: "OAuth 2.0 Attestation-Based Client Authentication"
  IANA-OAUTH:
    target: https://www.iana.org/assignments/oauth-parameters/
    title: "OAuth Parameters"

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
a time, and rolling it back waits out the same caches.

Capabilities let a client stage optional behavior without changing the
document. Suppose an updated release can accept a deferred token response
({{existing-drafts}}). The document continues to declare only what every
instance can process. The updated release sends its complete set, including the
illustrative `accept-deferred-response`, to one authorization server, since a
request set replaces the metadata default rather than adding to it
({{precedence}}). It sends other authorization servers nothing new, and older
releases are unaffected. Stopping is equally local while the value stays out of
the document. Once the document declares it, an instance withdraws it only by
sending a set without it, or `none`. Either way the client publishes one
document for every authorization server.

This works only for optional behavior. A metadata field that requires a
behavior applies at every authorization server that supports it: once
`dpop_bound_access_tokens` is true, such a server rejects token requests
without DPoP {{RFC9449}}. Such a field cannot be a capability ({{invariants}}),
and staging a change to it remains a problem for client metadata itself.

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
which values to signal, which is how it stages adoption ({{open-world}}); the
cohort itself is not signaled. Nor do capability values signal conformance to a
requirement, in either direction. A claim of conformance cannot be verified and
can be omitted by anyone who would violate the requirement, so enforcement keys
on the client's identity rather than the claim. A claim of non-conformance
cannot be sent by the clients that need it, which generally cannot be updated
to send anything.

# Conventions and Definitions {#terms}

{::boilerplate bcp14-tagged}

Capability:
: A named behavior that a client asserts it can process and that a server may
  choose to exercise.

Signal:
: To convey capability values to a server through one of the carriers defined
  in {{carriers}}; as a noun, the values so conveyed.

Effective capability set:
: The capability set that applies to a request after the carrier and precedence
  rules in {{carriers}} have been applied. Also called the effective set.

Terms not otherwise defined are used as in {{RFC6749}} and {{RFC9110}}.

# Overview {#overview}

A client tells a server what optional behavior it can process by signaling
capability values. A capability value is a short token drawn from a single
registry ({{iana-registry}}) shared by every extension.

Three carriers convey a set, chosen by what the request can hold:

- The `client_capabilities` request parameter, on requests a client makes to an
  authorization server ({{param}}).
- The `OAuth-Client-Capabilities` HTTP field, on requests that carry no OAuth
  parameters, such as protected resource requests ({{field}}).
- A `client_capabilities` member in client metadata, supplying a default when a
  request to an authorization server carries no signal ({{metadata}}).

Whichever carrier applies, the result is the request's effective capability
set: the values a server may act upon for that request. A request-level signal
replaces any metadata default rather than adding to it ({{precedence}}).

A server advertises the values it recognizes in its own metadata
({{discovery}}). Signaling never obliges a server to act. Under the invariants
in {{invariants}}, which every registered value has to meet, a signal that is
absent, removed, added, or untrue leaves the protocol no less secure.

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

For the request parameter, `capability-list` is applied after
`application/x-www-form-urlencoded` decoding. An empty value is treated as
omitted, as required by {{RFC6749}}. A non-empty value that does not match this
production, including a value with leading, trailing, or repeated spaces, is
invalid. A recipient MUST treat an invalid value as signaling the empty set and
MUST NOT reject the request solely because the value is invalid, except as
permitted by {{dos}}.

Capability values MUST NOT carry parameters. An extension that needs structured
detail alongside a capability defines a companion request parameter, or uses
`authorization_details` {{RFC9396}}. The registry is a flat vocabulary.

## Naming Guidance {#naming}

A capability value names a specific client behavior that a server may exercise
after receiving the value, not a document. `accept-deferred-response` is a
capability; `draft-gerber-oauth-deferred-token-response` is not. A
specification MAY register more than one value where a client can usefully
implement part of it.

A new revision of an extension whose client-side processing differs registers a
new value rather than reusing the old one. Registering the new value does not
retire the old one: its change controller MAY mark the old value obsolete, and
a server MAY continue to recognize it. A server that recognizes several
revisions of a behavior serves clients built against each of them from a single
deployment.

Because client-side processing may change while an extension is being revised,
an extension SHOULD register a value only once the processing it names is
stable. Unregistered values are not a general substitute in the interim.
Ignoring an unrecognized value protects a recipient that has never seen it, but
not one that has independently assigned the same token different semantics, in
which case the recipient exercises a behavior the sender cannot process.
Unregistered values therefore SHOULD be confined to deployments whose parties
have agreed on their meaning out of band, and early allocation SHOULD be sought
once deployment becomes interoperable, as {{RFC7120}} describes.

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

A protocol version is not a capability under any name, such as `oauth-2.1`,
because it changes which requests a server accepts rather than what a client
must process; see {{profiles}}.

## The `none` Sentinel {#none-value}

The token `none` is reserved for use as the complete value of the
`client_capabilities` request parameter or as the only member of the
`OAuth-Client-Capabilities` field. It denotes the empty set: the client signals
no capabilities. A client uses it to retract a statically declared set or, at a
protected resource, any out-of-band knowledge ({{precedence}}). It is
registered only to reserve the token ({{iana-registry}}); it is not a
capability and has no meaning in client metadata.

`none` MUST NOT appear together with any capability value. A server that
receives `none` alongside other values, in the request parameter or in a valid
field, MUST treat the signal as the empty set. Resolving the conflict to the
empty set, rather than rejecting the request, keeps the signal non-fatal
({{server-behavior}}). An invalid field is treated as absent even if it
contains `none` ({{field}}).

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
  implement the capability, and when a party other than the client asserts it.
  A capability MUST NOT substitute for client authentication, proof of
  possession, protocol validation, or other evidence required by the behavior
  it enables.

Two consequences follow. A client that claims a capability it lacks can receive
a response it cannot process, but CAP-2 and CAP-3 keep the false claim from
being accepted as authorization, authentication, or proof of a
security-relevant property. Any party able to send the request can assert a
value and elicit the enabled behavior, which CAP-3 requires to be safe in that
party's hands ({{unverified-signals}}). An adversary who removes values from a
signal denies optional behavior, which under CAP-1 is the safe direction.
Removing a signal that narrows a set instead restores a metadata default or
out-of-band knowledge ({{downgrade}}).

These invariants also serve as the admission criterion for the registry; see
{{extension-guidance}}.

# Relationship to Existing Mechanisms {#relationships}

scope:
: `scope` is an authorization construct. Its values are consented to, are often
  displayed to a user, and are carried in the resulting grant and access token.
  Capabilities are protocol mechanics: not consented to, not displayed, and by
  CAP-2 barred from affecting the grant.

grant_types and response_types:
: These select protocol flows and constrain which requests a registered client
  may make. Their absence can cause a request to fail. A capability instead
  describes optional response processing and has the safe-absence property in
  CAP-1.

Server metadata:
: {{RFC8414}} and {{RFC9728}} provide extensible discovery documents for
  authorization servers and protected resources. This specification defines a
  common member in both documents for the server-to-client direction and the
  carriers in {{carriers}} for the client-to-server direction.

Client attestation:
: The two mechanisms are complementary and address different questions: what
  the client can do, versus what can be proven about the client. See
  {{extension-guidance}}.

# Carriers {#carriers}

## The `client_capabilities` Request Parameter {#param}

client_capabilities:
: OPTIONAL. A space-delimited list of capability values, as defined in
  {{values}}.

The parameter is defined for use at the authorization endpoint and token
endpoint. A pushed authorization request can carry this parameter as specified
by {{RFC9126}}. The parameter MAY appear inside a Request Object {{RFC9101}}.
An extension MAY define its use at another endpoint that accepts OAuth request
parameters. An extension registering a capability value states every endpoint
at which the value is meaningful.

~~~ http-message
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
&client_id=https%3A%2F%2Fapp.example%2Fclient
&client_capabilities=accept-deferred-response
~~~
{: title="A capability signaled on a token request"}

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
This differs from an invalid value, which is not rejected ({{values}}).

Where the parameter would otherwise be carried in the query component of an
authorization request URI, and the client holds authorization server metadata
that includes `pushed_authorization_request_endpoint`
({{Section 5 of RFC9126}}), the client SHOULD use a pushed authorization
request instead, to bound URI growth and keep the list off the user agent.
Passing a Request Object {{RFC9101}} by value does not reduce URI size.

## The `OAuth-Client-Capabilities` HTTP Field {#field}

The `OAuth-Client-Capabilities` HTTP field allows a client to signal
capabilities on a request that has no OAuth request parameter surface, such as
a protected resource request.

The field asserts that the path which will process the response can process the
behavior. That path may be the sender alone, or the sender together with
another component on whose behalf it acts: an agent making a resource request
may relay a challenge to a component that completes it. The sender is
accountable for the assertion. Because the field does not necessarily identify
the OAuth client, client metadata supplies no default for it ({{precedence}}).

A client MUST NOT use the field on a request to an endpoint where the
`client_capabilities` request parameter is defined: the authorization, pushed
authorization request, and token endpoints, and any endpoint where an extension
defines the parameter. It uses the request parameter there ({{param}}), and an
authorization server MUST ignore the field on any request to such an endpoint.
Using only the parameter at these endpoints gives each request one unambiguous
effective set, and allows Request Object or pushed-request protections where
those apply. The field plays no part at other authorization server endpoints
either, such as the introspection {{RFC7662}}, revocation {{RFC7009}}, and
device authorization {{RFC8628}} endpoints ({{precedence}}); an extension that
needs a capability at one of them defines the request parameter there
({{param}}). At the client registration endpoint, a client declares
capabilities in client metadata ({{metadata}}).

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

A field whose only member is `none` ({{none-value}}) is valid and signals the
empty set. A client sends it to override any out-of-band knowledge an extension
defines ({{precedence}}).

A server whose response can vary with the field MUST include
`OAuth-Client-Capabilities` in the `Vary` field of every such response,
including responses to requests that omit the field, or use `Vary: *`
({{Section 12.5.5 of RFC9110}}).

An empty List is treated as an absent field ({{precedence}}). Structured Fields
serializes an empty List by omitting the field ({{Section 3.1 of RFC9651}}),
and parses an empty field value as an empty List.

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
string, does not conform to the `capability` production, or is `none`, the
field is invalid. A recipient MUST ignore an invalid field, deriving no
capabilities from it, and MUST NOT reject an otherwise-valid metadata document
or registration request solely because this field is invalid. This rule
concerns only the `client_capabilities` field; it does not change how the
containing protocol handles invalid JSON, a failed signature, or its other
required validation.

A party publishing or registering this metadata MUST NOT declare a capability
unless every client instance covered by that metadata can process the enabled
behavior, or every less-capable instance will override the default on its
requests. Clients with heterogeneous instances SHOULD omit the metadata field
and signal capabilities on each request.

A client metadata document published at a Client Identifier URL {{CIMD}} is
publicly retrievable, applies uniformly to every deployment using the URL, and
may be cached. Clients identified this way SHOULD treat the request parameter
in {{param}} as the primary carrier.

## Precedence {#precedence}

For requests directed to an authorization server, the effective capability set
is determined as follows:

1. If the request's OAuth parameters contain `client_capabilities`, its value
   is the effective set. A value that is invalid ({{values}}) or exceeds a limit
   ({{dos}}) is still present, and its effective set is empty.
2. Otherwise, the `client_capabilities` value from the client metadata that the
   authorization server considers authoritative for that client is the
   effective set.
3. If neither is present, the effective set is empty.

The `OAuth-Client-Capabilities` field plays no part in this determination. As
specified in {{field}}, an authorization server ignores the field at any
endpoint where the request parameter is defined.

Request values replace rather than augment metadata so that a less-capable
instance can retract a default. To retract everything, it sends
`client_capabilities=none`.

For a protected resource request, a valid field with at least one member is the
effective set and replaces any out-of-band knowledge an extension defines, even
if the server recognizes no value in it. Without such a field, the set is
empty, subject to that out-of-band knowledge; an absent field, an empty List,
and an invalid field are treated alike. A client that needs the empty set to
replace out-of-band knowledge sends `none` ({{none-value}}).

When an authorization request uses a Request Object, the authorization server
uses only the parameters inside it ({{Section 6.3 of RFC9101}}). A
`client_capabilities` value outside the Request Object is not used, and if the
Request Object contains no such value, step 2 applies. Inside a Request Object,
the value is a JSON string containing a `capability-list`; a value of any other
JSON type is invalid ({{values}}). An authorization request that uses a
`request_uri` from a pushed authorization request is built as defined in
{{RFC9101}} ({{Section 4 of RFC9126}}), so the same holds for the parameters
that were pushed: a `client_capabilities` value sent alongside the
`request_uri` is not used. A capability set in a software statement is client
metadata and remains subject to the request-level override above; signing the
statement does not turn a default into a per-request declaration.

## Scope of a Signal {#signal-scope}

A request signal applies only to that request, not to later requests in the
grant. Client metadata supplies a default for each request as described in
{{precedence}}; it does not make a prior request signal persist.

A capability in a pushed authorization request applies to the authorization
request represented by the resulting `request_uri`, and nothing else. A
capability governing token endpoint behavior MUST be in the effective set for
the token request; the authorization server MUST NOT infer it from an earlier
request in the grant. Because metadata can be cached or obtained from multiple
sources, a client SHOULD signal such a capability explicitly on the token
request rather than rely on a metadata default.

# Server Behavior {#server-behavior}

Presence of an unrecognized capability value MUST NOT cause a request to fail.

Signaling a capability does not entitle a client to the corresponding behavior.
A server retains discretion over whether to exercise optional behavior.

This specification does not define an error for an absent capability and does
not give any capability mandatory-to-understand semantics; see {{no-require}}.
An extension MAY define an error for a case in which the server cannot proceed
without a particular client-side behavior. Such an error reports the
extension's condition; it does not turn the signal into an authorization input.

A server MUST NOT promote a request-level capability set to durable client
metadata.

## Selecting Among Alternatives {#selection}

A server may have several ways to obtain what a request lacks. For example, a
protected resource might return a transaction authorization challenge, request
step-up authentication, or refuse. The effective capability set can help it
choose a path the client asserts it can complete.

A server MUST determine the assurance a request requires without reference to
the capability set. It MAY use the set to choose among paths that meet that
requirement. If no such path is available, it MUST refuse the request. Without
this rule, removing a value could steer the server to a weaker path,
reintroducing the downgrade CAP-1 prevents.

A path safe to issue unconditionally needs no gating signal, but may warrant
one to prevent the server from selecting a path the client cannot complete. See
{{extension-guidance}}.

# Discovery {#discovery}

client_capabilities_supported:
: OPTIONAL. A JSON array of strings containing the capability values that the
  server recognizes and may act upon.

This metadata member is defined for authorization server metadata {{RFC8414}}
and for protected resource metadata {{RFC9728}}.

The array MUST NOT contain `none`. If the value is not an array, or any element
is not a string, does not conform to the `capability` production, or is `none`,
the value of this member is invalid and MUST be ignored in its entirety.

A client that holds a server's `client_capabilities_supported` SHOULD signal
only values that appear in it. This does not apply to `none` ({{none-value}}),
which the list never contains: if filtering leaves no value and the client
needs to override a metadata default or out-of-band knowledge, it sends `none`.
A client that does not hold the list MAY signal values without retrieving it
first; a server that does not recognize a value ignores it. Advertising
recognized values lets a client that holds the list bound request size and
fingerprinting exposure, following the pattern of Client Hints {{RFC8942}}.

Absence of `client_capabilities_supported` does not indicate that the server
fails to support this specification.

Advertising a value is not a commitment to exercise the behavior; see
{{server-behavior}}.

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

- Register a behavior, not a specification. See {{values}}.
- State the absent-signal behavior, not only the behavior enabled. An extension
  that cannot describe a fallback at least as conservative as the pre-extension
  behavior has not satisfied CAP-1, whatever the value is named.
- Prefer server-side discovery where it works. If the client-side behavior can
  be specified as a requirement conditioned on something the server advertises
  in its own metadata ({{RFC8414}} or {{RFC9728}}), specify it that way and
  register no capability. A capability is for behavior that cannot be made
  mandatory because the server cannot learn whether the client implements it.
- State, in the registration, the carriers and endpoints at which the value is
  meaningful.

Issuer-wide behavior is often the intended design, and coupling it to a
per-issuer metadata flag is a legitimate choice. Where per-client or fractional
rollout of a behavior that meets {{invariants}} is a requirement, however, an
extension SHOULD NOT couple the behavior to such a flag, because it then
becomes all-or-nothing for every client of the issuer; gate it on a capability
instead. {{RFC9207}} illustrates the trade-off: coupling the advertisement to a
server-wide delivery commitment allows a client to enforce that `iss` is
present, but the feature cannot be rolled out per client. Rolling out a change
in request-processing rules, such as OAuth 2.1, is not a behavior a capability
can gate; see {{profiles}}.

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
third-party modification but does not prove implementation. See {{precedence}}.

## Downgrade {#downgrade}

Because capability signals may be removed by an adversary, an extension MUST
define a safe absent-signal fallback. If the enabled behavior is how a server
obtains something it requires, the fallback is refusal, not proceeding without
it. With such a fallback, removal costs client functionality, never a server
security property. Removing a signal that narrows a set widens it instead:
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

For the same reason, CAP-1 bars an extension from using a capability to enable
a security check that the server otherwise skips. Such a check belongs in
policy or an authenticated negotiation mechanism.

## Denial of Service {#dos}

A capability list is attacker-controllable in size. Servers MUST apply finite
limits to the encoded length, number of members, and resources consumed while
parsing a signal. A signal that exceeds a limit MUST be treated as invalid: a
request parameter then signals the empty set ({{values}}), and a field is
treated as absent ({{field}}); a server MAY instead reject the request using an
error response appropriate to the endpoint or application protocol. In
particular, `invalid_request` is available at OAuth endpoints, while a
protected resource can use an application-specific response.

Acting on a falsely asserted capability can also consume server resources. An
extension specification MUST analyze this cost and define any necessary
rate-limiting, state-allocation, or replay protections. A capability signal
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
and seeking early allocation.

# Privacy Considerations {#privacy-considerations}

A capability set discriminates over the client population and contributes to
fingerprinting. On the front channel it is visible to the user agent, and in a
publicly retrievable client metadata document it is visible to anyone. The
marginal disclosure to an authorization server is smaller, since it already
receives a `client_id` that often identifies the software, but a capability set
can still add information.

Clients that consider their capability set sensitive SHOULD use {{RFC9126}} or
an encrypted Request Object as defined in {{RFC9101}}, SHOULD, when they hold
the server's `client_capabilities_supported`, restrict signaled values to those
it lists, and SHOULD NOT publish the set in public client metadata. A signed
but unencrypted Request Object provides integrity, not confidentiality.

Capability values MUST NOT encode information about an end user or a specific
device. Specifications defining capabilities whose availability depends on the
deployment environment MUST assess whether signaling them creates a useful
fingerprint and SHOULD choose names that describe behavior without exposing
implementation details.

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
  criterion in {{extension-guidance}}, and that its registered absent-signal
  behavior is at least as conservative as what the server would apply had the
  value never been defined;
- confirm that the specification defines the optional behavior enabled and
  identifies every applicable carrier and endpoint;
- confirm that the specification meets the requirements this document places
  on extensions, including those in {{param}}, {{selection}},
  {{extension-guidance}}, {{downgrade}}, {{dos}}, and
  {{privacy-considerations}};
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
: Reserved. Denotes the empty capability set.

Status:
: current

Absent-Signal Behavior:
: Not applicable. `none` is a sentinel rather than a capability.

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

The following example shows a pushed authorization request carrying the
parameter, which keeps the value off the authorization URI. The value applies
only to that authorization request ({{signal-scope}}); the example illustrates
the carrier:

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

The following example shows the claims of a Request Object carrying the
parameter. The value is a JSON string, not an array ({{precedence}}):

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

The following example shows the same capability on the token request; the
earlier signal does not carry over ({{signal-scope}}):

~~~ http-message
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=SplxlOB...
&client_id=https%3A%2F%2Fapp.example%2Fclient
&redirect_uri=https%3A%2F%2Fapp.example%2Fcb
&code_verifier=dBjftJeZ...
&client_capabilities=accept-deferred-response
~~~
{: title="Signaling at the endpoint where the behavior occurs"}

The following example shows a client registration request {{RFC7591}} that
declares a default capability set. Every instance covered by the registration
can process the behavior or overrides the default on its requests
({{metadata}}), as the next example shows:

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

The following example shows a registered client retracting the capability
its metadata declares, on a request made by an instance that cannot outlive
the request:

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

The following examples show excerpts of authorization server metadata
{{RFC8414}} and protected resource metadata {{RFC9728}} that advertise
recognized values ({{discovery}}):

~~~ json
{
  "issuer": "https://as.example.com",
  "token_endpoint": "https://as.example.com/token",
  "client_capabilities_supported": ["accept-deferred-response"]
}
~~~
{: title="Authorization server metadata excerpt"}

~~~ json
{
  "resource": "https://api.example.com",
  "authorization_servers": ["https://as.example.com"],
  "client_capabilities_supported": ["txn-challenge"]
}
~~~
{: title="Protected resource metadata excerpt"}

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
  returns an error.

Carriers:
: request parameter, client metadata

Endpoints:
: token endpoint

Change Controller:
: The party responsible for the registration

Specification Document(s):
: {{DTR}}

# Applying This Specification to Existing Drafts {#existing-drafts}

This appendix is informative and describes how the two extensions that
motivated this work would use the mechanism.

Deferred Token Response:
: `completion_mode=deferred` becomes `client_capabilities` containing
  `accept-deferred-response`. The authorization server still MUST NOT defer
  unless the value is in the request's effective set. {{signal-scope}}
  requires the value in the token request's effective set; a signal at an
  earlier endpoint has no effect on the token response. The proposed
  single-purpose registry is subsumed by {{iana-registry}}, and the
  `deferred_token_response_supported` authorization server metadata Boolean
  by `client_capabilities_supported` containing the value. Either suffices to
  show that a server recognizes the capability, and a disagreement between
  them affects only which values a client chooses to send ({{discovery}}).

Transaction Authorization Challenge:
: `Accept-Txn-Challenge: ?1` becomes
  `OAuth-Client-Capabilities: txn-challenge`. The Boolean becomes membership
  of `txn-challenge` in the request's effective set ({{precedence}}).
  Out-of-band knowledge of support still applies, but only when the request
  carries no valid field.

# Design Rationale {#rationale}

This appendix is informative.

## Survey of Existing Mechanisms {#survey}

OAuth has static client declarations {{RFC7591}}, extensible server metadata
{{RFC8414}} {{RFC9728}}, and per-extension request parameters, HTTP fields, or
signals implied by construction, such as a DPoP proof {{RFC9449}}. Static
metadata cannot express per-request or per-instance variation, while server
metadata runs only server to client.

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
defaults ({{open-world}}).

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

A request set replaces the metadata default rather than adding to it
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
  rather than a dedicated field ({{why-not-prefer}}). The dedicated field keeps
  `Vary` precise and uses Structured Fields parsing; a preference reuses an
  existing field.
- Whether the `.` and `:` characters the syntax allows should carry any
  structure. No structure is needed today: a revision with different
  client-side processing registers a new value ({{values}}).
- Whether client software capabilities and running instance capabilities are
  adequately separated by the replacement rule in {{precedence}}, or whether
  instance-level identity mechanisms should carry a capability set of their
  own.

# Acknowledgments
{:numbered="false"}

This work was motivated by {{DTR}} and {{TXN-CHALLENGE}}, whose authors
independently identified the same requirement and whose divergent solutions
made the general problem visible.
