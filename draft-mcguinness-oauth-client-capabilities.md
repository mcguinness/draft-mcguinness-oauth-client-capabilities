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
  RFC8942:
  RFC9396:
  RFC9449:
  RFC9635:
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
only optional server behavior, so that their absence is always safe.

--- middle

# Introduction

A growing number of OAuth 2.0 {{RFC6749}} extensions share one normative shape:

> The server MUST NOT do X unless the client has signaled that it can process X.

The constraint exists because these extensions change what a client receives in
response to an otherwise ordinary request. A client that cannot parse the new
response is not merely unable to use the extension; it fails. Deployment
therefore depends on the server knowing, in advance, that the client will cope.

Two current extensions illustrate the pattern, and disagree on how to carry it.
{{DTR}} defines a `completion_mode` request parameter and requires that an
authorization server "MUST NOT defer a response to a request whose
`completion_mode` does not include `deferred`". {{TXN-CHALLENGE}} defines an
`Accept-Txn-Challenge` HTTP field and requires that a protected resource "MUST
NOT return a transaction authorization challenge unless the request includes an
`Accept-Txn-Challenge` header field with a true value, or the protected resource
has out-of-band knowledge that the client supports this specification".

The requirements are structurally identical. The carriers are not.

## The Carrier Asymmetry {#asymmetry}

The two extensions did not diverge arbitrarily. Neither carrier can perform the
other's function.

An HTTP field works for {{TXN-CHALLENGE}} because the client makes the resource
request itself, directly, over HTTP. That request has no OAuth parameter
surface: a capability cannot be attached to `GET /transfers/42`.

An HTTP field cannot work for {{DTR}} at the authorization endpoint, because
the OAuth front channel is mediated by a user agent. The client does not issue
the authorization request; it constructs a URI and hands it to a browser, which
issues the request with its own fields. Any client-originated HTTP field is
lost at the redirect boundary.

A general mechanism therefore cannot be an HTTP field alone, and cannot be a
request parameter alone. Two request carriers over one shared vocabulary is the
minimum that covers OAuth's actual topology.

## Why Open-World Deployment Makes This Urgent {#open-world}

Classic OAuth had one place to establish what a client could do: registration.
The client metadata of {{RFC7591}} is already a capability declaration:
`grant_types`, `response_types`, `token_endpoint_auth_method`,
`dpop_bound_access_tokens` {{RFC9449}}, and
`require_pushed_authorization_requests` {{RFC9126}} all describe client
behavior. It is a static declaration, agreed once.

Deployments that identify clients by a published metadata document {{CIMD}},
that operate autonomous software instances, or that otherwise pair clients and
authorization servers that have never transacted before have no registration
handshake in which to negotiate. The first message is the request. What the
server needs to know about the client's processing ability must be carried in
that request, or discoverable from a document the client publishes rather than
one the server issued.

Per-extension parameters remain workable where a small number of extensions are
deployed between parties with a prior arrangement. What breaks is accumulation
against an unbounded client population.

Per-extension signals accumulate in both directions. Each capability relevant
before the token request adds a parameter to the authorization URI, which travels
through a redirect the user agent can read, log, truncate, and modify. Each
capability relevant at a resource adds a field to every protected resource
request for the life of the deployment; the `Accept-*` family, which
`Accept-Txn-Challenge` correctly follows, is one field per feature by
construction. Each signal separately costs a parameter registration, usually
client and server metadata registrations, and sometimes an HTTP field
registration.

The motivating behaviors face both ways: one is signaled to an authorization
server and one to a resource server. A per-extension design therefore pays the
cost in both places at once, which is the asymmetry in {{asymmetry}} seen from
the cost side.

## What This Specification Does Not Change

This specification defines a carrier and a vocabulary. It does not define any
capability values, reserves the `none` sentinel in {{none-value}}, does not
change any existing parameter, and does not require existing extensions to
migrate. It is designed so that extensions may adopt it incrementally.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Capability:
: A named behavior that a client asserts it can process and that a server may
  therefore choose to exercise.

Signal:
: The act of a client conveying a capability value to a server through one of
  the carriers defined in {{carriers}}.

Effective capability set:
: The capability set that applies to a request after the carrier and
  precedence rules in {{carriers}} have been applied.

Terms not otherwise defined are used as in {{RFC6749}} and {{RFC9110}}.

# Capability Values {#values}

## Syntax

A capability value is a bare token. The syntax uses ABNF {{RFC5234}},
including its `ALPHA`, `DIGIT`, and `SP` core rules:

~~~ abnf
capability        = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." / ":" )
capability-list   = capability *( SP capability )
~~~
{: title="Capability value syntax"}

This character set is deliberately the intersection of two constraints: the
value is valid as a sequence of `NQCHAR` in a form-encoded OAuth parameter
({{RFC6749}}, Appendix A), and valid as an `sf-token` in a structured field
({{RFC9651}}, Section 3.3.4). A single registered value is therefore usable in
both carriers with no transformation.

Capability values are case-sensitive. The order of values is not significant,
and duplicates MUST be ignored.

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

## Naming Guidance

A capability value names a specific client behavior that a server may exercise
after receiving the value, not a document. `accept-deferred-response` is a
capability; `draft-gerber-oauth-deferred-token-response` is not. A
specification MAY register more than one value where a client can usefully
implement part of it.

A new version of an extension whose client-side processing differs registers a
new value rather than reusing the old one, so that a server can distinguish the
two.

## The `none` Sentinel {#none-value}

The token `none` is reserved for use as the complete value of the
`client_capabilities` request parameter. It denotes the empty set: the client
signals no capabilities beyond base OAuth. It exists so that a client can
explicitly retract a statically declared set, as described in {{precedence}}.
It is not a capability value and has no meaning in the HTTP field or client
metadata carriers.

`none` MUST NOT appear together with any capability value. A server that
receives `none` alongside other values MUST treat the signaled set as empty.
Resolving the conflict in favor of the empty set rather than rejecting the
request keeps the semantics of a capability signal non-fatal, consistent with
{{server-behavior}}, and errs toward the direction CAP-1 makes safe.

# Capability Invariants {#invariants}

The following three constraints apply to every registered capability value and
to every use of the carriers in {{carriers}}. They are the basis on which the
security analysis in {{security-considerations}} rests, and they are normative.

CAP-1:
: A capability MUST only enable optional server behavior. Removing a capability
  value from the effective capability set MUST NOT cause a server to apply
  weaker client authentication, weaker sender constraining, weaker user
  authentication, or a more permissive policy than it would have applied had
  the value never been defined. Absence MUST be safe.

CAP-2:
: A capability MUST NOT establish what a client is permitted to obtain or be
  accepted as evidence in an authorization decision. A capability describes
  what a client is able to process. Servers MUST NOT grant scope, relax consent
  requirements, or extend token lifetimes on the basis of a signaled
  capability.

CAP-3:
: A server MUST NOT rely on a capability signal being truthful. The security
  properties of the enabled behavior MUST hold even when the client does not
  implement the capability. A capability MUST NOT substitute for client
  authentication, proof of possession, protocol validation, or other evidence
  required by the behavior it enables.

Two consequences follow. Capabilities are self-asserted, and a client claiming
one it lacks can receive a response it cannot process; CAP-2 and CAP-3 keep a
false claim from being accepted as authorization, authentication, or proof of a
security-relevant property, though an extension must still analyze its
operational cost ({{dos}}). And an adversary able to modify a request, including
the user agent on the front channel, can remove values and degrade the client to base OAuth. Under CAP-1 that is the
safe direction, at the cost of optional functionality.

These invariants also serve as the admission criterion for the registry; see
{{extension-guidance}}.

# Carriers {#carriers}

## The `client_capabilities` Request Parameter {#param}

client_capabilities:
: OPTIONAL. A space-delimited list of capability values, as defined in
  {{values}}.

The parameter is defined for use at the authorization endpoint and token
endpoint. Because a pushed authorization request carries authorization request
parameters, it can carry this parameter as specified by {{RFC9126}}. The
parameter MAY appear inside a Request Object {{RFC9101}}. An extension MAY
define its use at another endpoint that accepts OAuth request parameters. An
extension registering a capability value states every endpoint at which the
value is meaningful.

The parameter is not defined for the client registration endpoint. A
registration request carries a JSON body rather than form-encoded parameters,
so a client declares capabilities there using the metadata field in
{{metadata}}.

A client MAY send `client_capabilities` to any authorization server without
prior knowledge of whether the server implements this specification at the
authorization or token endpoint. {{RFC6749}}, Sections 3.1 and 3.2 require an
authorization server to ignore unrecognized request parameters at those
endpoints. Specifications that define its use at another endpoint MUST ensure
that unrecognized request parameters are ignored there. Whether a server acted
on the signal is revealed by the server's behavior, which is what an advisory
signal requires. No negotiation handshake is needed and none is defined.

The parameter MUST NOT be sent with an empty value. A client that wants an
empty effective set omits the parameter when no metadata default applies and
sends `none` when it needs to override such a default.

Where the parameter would otherwise be carried in the query component of an
authorization request URI, clients SHOULD instead use a pushed authorization
request {{RFC9126}}. This bounds the growth of the authorization URI and keeps
the capability list off the user agent. A Request Object {{RFC9101}} provides
integrity protection; an encrypted Request Object also provides
confidentiality, but a Request Object passed by value does not reduce URI size.
PAR is a SHOULD rather than a MUST because CAP-1 makes query carriage safe, if
undesirable.

## The `OAuth-Client-Capabilities` HTTP Field {#field}

The `OAuth-Client-Capabilities` HTTP field allows a client to signal capabilities
on a request that has no OAuth request parameter surface, most importantly a
protected resource request. A protected resource is also where alternative
challenge paths most often coexist, so the field is where a capability set is most
likely to inform a choice among them rather than gate a single behavior; see
{{selection}}.

Its value is a Structured Fields List ({{RFC9651}}, Section 3.1). Each member
MUST be an Item whose bare item is a Token containing a capability value as
defined in {{values}}:

~~~ http-message
GET /transfers/42 HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGci...
OAuth-Client-Capabilities: txn-challenge
~~~
{: title="Signaling a capability on a protected resource request"}

Senders MUST NOT generate Inner List members, members of another bare-item
type, or parameters. A recipient MUST parse the field as a Structured Fields
List. If parsing fails, or if any member is not a Token Item, the recipient
MUST treat the field as absent. A recipient MUST ignore parameters and
unrecognized capability values. The order of members is not significant, and
duplicate values MUST be ignored.

The `none` sentinel defined in {{none-value}} is not a capability value and
MUST NOT be sent in this field. A recipient MUST ignore a member whose value is
`none`.

A server whose response varies with the field MUST include
`OAuth-Client-Capabilities` in the `Vary` field of the response, or use
`Vary: *`, per {{RFC9110}}, Section 12.5.5.

The field is defined only for requests that have no OAuth request parameter
surface. A client MUST NOT use the field on a request at an endpoint where the
`client_capabilities` parameter is defined; it uses {{param}} there instead. An
authorization server MUST ignore the field on any request to such an endpoint.

At the authorization endpoint, the HTTP request is issued by a user agent, so a
field on it cannot be attributed to the client. At authorization server
endpoints where the parameter is defined, using one carrier gives the request
one unambiguous effective set and allows the signal to receive the protections
of a Request Object or pushed authorization request where those mechanisms
apply.

An empty List and an absent field are equivalent: both signal the empty set.

## Client Metadata Declaration {#metadata}

client_capabilities:
: OPTIONAL. A JSON array of strings, each a capability value as defined in
  {{values}}, describing the default capabilities of the client identified by
  the metadata.

This is a client metadata field as defined in {{RFC7591}}, Section 2. One
definition covers three cases: metadata registered with an authorization
server, a client metadata document published at the client's identifier
{{CIMD}}, and metadata carried in a software statement.

Depending on the metadata mechanism and deployment model, the metadata can
describe client software, a deployed client, or both. A particular request can
originate from an instance with a more constrained capability set; see
{{precedence}}.

Every array element MUST conform to the `capability` production in {{values}}.
The array MUST NOT contain `none`. An absent field and an empty array both
denote the empty set. Order is not significant, and recipients MUST ignore
duplicate and unrecognized values. If any element is not a string or does not
conform to the `capability` production, the metadata field is invalid. A
recipient MUST NOT derive any capabilities from an invalid field; the
containing metadata protocol determines whether the document or request is
rejected or the field is ignored.

A party publishing or registering this metadata MUST NOT declare a capability
unless every client instance covered by that metadata can process the enabled
behavior, or every less-capable instance will override the default on its
requests. Clients with heterogeneous instances SHOULD omit the metadata field
and signal capabilities on each request.

A client metadata document published at a Client Identifier URL {{CIMD}} is
publicly retrievable, applies uniformly to every deployment using the URL, and
may be cached by an authorization server. A capability declared there is
therefore public and shared by every instance, and a change might not take
effect until each authorization server refreshes its cached copy according to
HTTP caching and any locally imposed bounds. Clients identified this way SHOULD
treat the request parameter in {{param}} as the primary carrier.

## Scope of a Signal {#signal-scope}

A capability signal in a request applies only to that request. It does not
establish a property of the client that persists across the several requests of
a grant. Client metadata supplies a default for each request as described in
{{precedence}}; it does not cause an explicit signal on one request to persist.

This matters most where the behavior a capability enables occurs at a different
endpoint from the one at which a client first signals it. A client that signals
a capability in a pushed authorization request has signaled it for the
authorization request that the resulting `request_uri` stands in for, and for
nothing else. Where the capability governs behavior at the token endpoint, the
capability MUST be in the effective set for the token request, and the
authorization server MUST NOT infer it from an earlier request in the same
grant. Where metadata can be cached or obtained from more than one source, a
client might not know which value the authorization server currently applies.
A client SHOULD therefore signal such a capability explicitly on the token
request rather than relying on a metadata default.

Where a capability is meaningful at more than one endpoint, its registration
({{iana-registry}}) records which endpoints those are.

## Precedence {#precedence}

For requests directed to an authorization server, the effective capability set
is determined as follows:

1. If the request's OAuth parameters contain `client_capabilities`, its value
   is the effective set.
2. Otherwise, the `client_capabilities` value from the client metadata that the
   authorization server considers authoritative for that client is the
   effective set.
3. If neither is present, the effective set is empty.

The `OAuth-Client-Capabilities` field plays no part in this determination. As
specified in {{field}}, an authorization server ignores the field at any
endpoint where the request parameter is defined.

The rule is replacement rather than union because retraction is a requirement: a
deployment may lack a capability its metadata declares, as a batch-job client
cannot return in six hours for a deferred response. Under union it could never
say so. To retract everything, a client sends `client_capabilities=none`.

A protected resource generally does not have the client's metadata to consult.
For a protected resource request bearing a valid field, the field is the
effective set. Without a valid field, the effective set is empty, subject to
any out-of-band knowledge provision an individual extension defines.

When an authorization request uses a Request Object, the authorization server
MUST determine the request parameter value according to {{RFC9101}}. In
particular, a `client_capabilities` value inside the Request Object takes
precedence over a duplicate value outside it. A capability set in a software
statement is client metadata and remains subject to the request-level override
above; signing the statement does not turn a default into a per-request
declaration.

# Server Behavior {#server-behavior}

A server MUST ignore capability values it does not recognize. Presence of an
unrecognized value MUST NOT cause a request to fail.

Signaling a capability does not entitle a client to the corresponding behavior.
A server retains full discretion over whether to exercise any optional
behavior, on the basis of policy, risk assessment, or operational state.

This specification does not define an error for an absent capability and does
not give any capability mandatory-to-understand semantics. An extension MAY
define an error for a case in which the server cannot proceed without a
particular client-side behavior. Such an error reports that extension's
condition; it does not make the capability signal an authorization or policy
input. This specification defines no analogue of the SIP `Require` field
{{RFC3261}}. See {{rationale}}.

A server SHOULD NOT promote a request-level capability set to durable client
metadata. Client metadata persists according to the mechanism that provides it,
but a subsequent request can override that default with a different set.

## Selecting Among Alternatives {#selection}

A server may have more than one way to obtain what a request lacks. A protected
resource that cannot authorize an operation from the access token alone might
return a transaction authorization challenge, request step-up authentication, or
refuse, and which of those the client can act on differs. The effective
capability set lets the server choose a path the client can complete rather than
choosing one and hoping.

This use carries one requirement. A server MUST determine the assurance a request
requires without reference to the signaled capability set. It MAY then use the set
to choose among paths that meet that requirement, and MUST refuse the request
where no signaled path meets it. Otherwise selection reintroduces the downgrade
CAP-1 exists to prevent: removing a value would steer the server to a different
path, and where the alternatives are not equivalent for the decision at hand, the
weaker one is what the request gets.

Selection needs no capability values beyond those that gating already requires. A
path a server can take safely whatever the client does, such as an error a client
either understands or reports as a failure, never needed a signal; only the paths
that would break an unprepared client do.

# Discovery {#discovery}

client_capabilities_supported:
: OPTIONAL. A JSON array of strings containing the capability values that the
  server recognizes and may act upon.

The field is defined for authorization server metadata {{RFC8414}} and for
protected resource metadata {{RFC9728}}.

Every array element MUST conform to the `capability` production in {{values}}.
The array MUST NOT contain `none`. Order is not significant, and clients MUST
ignore duplicate and unrecognized values. If any element is not a string or
does not conform to the `capability` production, the metadata field is invalid
and MUST be ignored in its entirety.

The direction follows a pattern used by Client Hints {{RFC8942}}: the server
advertises what it recognizes so that the client can avoid sending unsupported
values. This bounds front-channel growth ({{open-world}}) and the fingerprinting
surface ({{privacy-considerations}}).

Clients SHOULD signal only capability values that appear in
`client_capabilities_supported`, where the server publishes it. A client MAY
signal values absent from the list, and MAY signal values to a server that
publishes no list at all; a server that does not recognize a value ignores it.

Absence of `client_capabilities_supported` does not indicate that the server
fails to support this specification.

# Guidance for Extension Specifications {#extension-guidance}

An extension that needs a client to signal a processing capability SHOULD
register a value in the registry established in {{iana-registry}} rather than
define a dedicated parameter or field.

The admission criterion follows from {{invariants}} and is best applied as a
single test:

> If an implementer would want the value to be attested, it is not a
> capability.

A property that must be trustworthy to be useful is an assurance, and belongs
in client attestation {{ABCA}}, a software statement {{RFC7591}}, or an
equivalent signed structure. Capabilities are assertions rather than
assurances. The invariants in {{invariants}} are what make that acceptable. An
extension that finds itself wanting to bind a capability to a key, or to trust
it in a policy decision, has misclassified it.

Additional points of discipline:

- Register a behavior, not a specification. See {{values}}.
- State the absent-signal behavior, not only the behavior enabled. An extension
  that cannot describe a fallback at least as conservative as the pre-extension
  behavior has not satisfied CAP-1, whatever the value is named.
- Prefer server-side discovery where it works. If the client-side behavior can
  be specified as a requirement conditioned on something the server advertises
  in its own metadata ({{RFC8414}} or {{RFC9728}}), specify it that way and
  register no capability. A capability is for behavior that cannot be made
  mandatory, because it is genuinely optional for the client and the server
  therefore cannot discover conformance.
- State, in the registration, the carriers and endpoints at which the value is
  meaningful. A value meaningful at the token endpoint is usually meaningless
  on a protected resource request, and a registry that says so prevents clients
  from signaling noise.

# Relationship to Existing Mechanisms {#relationships}

scope:
: `scope` is an authorization construct. Its values are consented to, are often
  displayed to a user, and are carried in the resulting grant and access token.
  Capabilities are protocol mechanics: not consented to, not displayed, and by
  CAP-2 barred from affecting the grant. Overloading `scope` would place
  non-authorization values in front of users and inside issued tokens.

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
: See {{extension-guidance}}. The two mechanisms are complementary and address
  different questions: what the client can do, versus what can be proven about
  the client.

# Security Considerations {#security-considerations}

The security properties of this mechanism rest on {{invariants}}, which are
stated normatively rather than here because they constrain the registry rather
than any single deployment. This section describes what follows from them.

## Signals Are Not Proof

A capability signal is a client assertion, not proof that the client
implements the capability. Transport security, client authentication, a
Request Object, or a signed software statement can establish who made the
assertion and protect its integrity. None of those mechanisms proves that the
assertion is true.

On the front channel, a bare request parameter is modifiable by the user agent
and by anything else able to alter the authorization request. Injection of a
value can cause a server to send a response the client cannot process, and
removal can deny optional functionality. CAP-1 through CAP-3 ensure that
neither action is accepted as a reason to weaken a security property, grant
authorization, or skip evidence required by the enabled behavior.

Servers MUST NOT treat a capability signal as evidence of client identity,
client software version, or client trustworthiness.

## Downgrade

Because capability signals may be removed by an adversary, an extension MUST
define an absent-signal fallback that is itself safe. Where the enabled
behavior is how a server obtains something it requires, the fallback is to
refuse the operation rather than to proceed without it. A resource server that
cannot issue a transaction authorization challenge because the client did not
signal the capability denies the request; it does not treat the transaction as
authorized. Removal costs the client functionality, never the server a security
property.

The inverted form to avoid is an extension whose enabled behavior is what
applies a check the server would otherwise skip: "the client can perform a
stronger check, so enable it". There, removing the signal removes the check.
Such a check belongs in policy, negotiated through mechanisms that are
authenticated.

## Denial of Service {#dos}

A capability list is attacker-controllable in size. Servers MUST apply finite
limits to the encoded length, number of members, and resources consumed while
parsing a signal. A signal that exceeds a limit MUST be treated as signaling
the empty set; a server MAY instead reject the request using an error response
appropriate to the endpoint or application protocol. In particular,
`invalid_request` is available at OAuth endpoints, while a protected resource
can use an application-specific response.

Acting on a falsely asserted capability can also consume server resources. An
extension specification MUST analyze this cost and define any necessary
rate-limiting, state-allocation, or replay protections. A capability signal
does not authorize the client to consume unbounded work.

## Interaction with Signed Requests

Where a Request Object {{RFC9101}} or software statement carries a capability
set, the signature protects the assertion from modification. This does not make
the values proof of implementation; a signature attests to the assertion, not
its truth. The distinct precedence rules for Request Objects and software
statements are specified in {{precedence}}.

# Privacy Considerations {#privacy-considerations}

A capability set discriminates over the client population and contributes to
fingerprinting. On the front channel it is visible to the user agent, and in a
publicly retrievable client metadata document it is visible to anyone.

Three factors reduce the exposure. The authorization server already receives a
`client_id`, which often identifies the software, though a capability set can
still add information. {{discovery}} lets a client send only values the server
will act upon. And the recommendation in {{param}} to use a pushed authorization
request keeps the set out of the authorization URI and away from the user agent;
a signed but unencrypted Request Object does not, since it provides integrity
rather than confidentiality.

Clients that consider their capability set sensitive SHOULD use {{RFC9126}} or an
encrypted Request Object as defined in {{RFC9101}}, SHOULD restrict signaled
values to those advertised in `client_capabilities_supported`, and SHOULD NOT
publish the set in public client metadata.

Capability values MUST NOT encode information about an end user or a specific
device. Specifications defining capabilities whose availability depends on the
deployment environment MUST assess whether signaling them creates a useful
fingerprint and SHOULD choose names that describe behavior without exposing
implementation details.

# IANA Considerations

## OAuth Client Capabilities Registry {#iana-registry}

This specification requests that IANA establish an "OAuth Client Capabilities"
registry in the "OAuth Parameters" registry group. Values are registered on a
Specification Required basis as defined in {{RFC8126}}, Section 4.6.

The registry contains the following fields:

Capability Value:
: The token, conforming to the `capability` production in {{values}}.

Description:
: A brief description of the client behavior signaled by the value.

Absent-Signal Behavior:
: What the server does when the value is not in the effective set. Recording
  this makes CAP-1 in {{invariants}} checkable at registration time rather than
  aspirational.

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
- consider the security, privacy, interoperability, and operational effects of
  false assertion and signal removal; and
- reject values that duplicate the semantics of an existing registration or
  differ from one only in letter case.

The designated experts should presume that a registration is acceptable when
these requirements are met. They may obtain feedback from the OAuth Working
Group or its successor, but working group consensus is not required.

The registry's initial content is:

Capability Value:
: `none`

Description:
: Reserved. Denotes the empty capability set.

Absent-Signal Behavior:
: Not applicable. `none` is a sentinel rather than a capability.

Carriers:
: request parameter

Endpoints:
: Any authorization server endpoint at which the request parameter is defined

Change Controller:
: IETF

Specification Document(s):
: This specification, {{none-value}}

## OAuth Parameters Registry

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

## OAuth Dynamic Client Registration Metadata Registry

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

## OAuth Authorization Server Metadata Registry

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

## OAuth Protected Resource Metadata Registry

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

## HTTP Field Name Registry

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

# Examples

This document registers no capability values. `accept-deferred-response` below is
illustrative, corresponding to a behavior described in {{existing-drafts}}.
Line breaks in the form-encoded request bodies are for display only.

A pushed authorization request carrying the capability, keeping it off the
authorization URI:

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

The same capability on the token request. Because the behavior affects the token
response, the earlier signal does not carry over; see {{signal-scope}}:

~~~ http-message
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=SplxlOB...
&client_id=https%3A%2F%2Fapp.example%2Fclient
&client_capabilities=accept-deferred-response
~~~
{: title="Signaling at the endpoint where the behavior occurs"}

A deployment of the same software whose metadata declares the capability,
retracting it because this process cannot outlive the request:

~~~ http-message
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=SplxlOB...
&client_id=https%3A%2F%2Fapp.example%2Fclient
&client_capabilities=none
~~~
{: title="Explicit retraction by a constrained deployment"}

# Applying This Specification to Existing Drafts {#existing-drafts}

This appendix is informative and describes how the two extensions that motivated
this work would use the mechanism. Neither is required to migrate.

Deferred Token Response:
: `completion_mode=deferred` becomes `client_capabilities` containing
  `accept-deferred-response`, and the normative rule is unchanged in shape: the
  authorization server MUST NOT defer unless the request signals the capability.
  The "OAuth Completion Mode Values" registry {{DTR}} proposes becomes
  unnecessary, being a single-value registry subsumed by {{iana-registry}}.
  Because deferral occurs in the token response, {{signal-scope}} requires the
  capability in the effective set for the token request, matching the draft's
  existing rule that the client signals opt-in "on the originating grant's token
  endpoint request"; the preceding-endpoint occurrence remains an optional hint.

Transaction Authorization Challenge:
: `Accept-Txn-Challenge: ?1` becomes `OAuth-Client-Capabilities: txn-challenge`.
  The normative rule and the out-of-band knowledge provision are unchanged. The
  value type changes from Boolean to list membership, which simplifies the
  draft's rule that a false value has the same semantics as omission: absence
  from the list is the only way to express it.

Neither extension loses expressiveness. Both stop owning a carrier.

# Design Rationale {#rationale}

This appendix is informative.

## Survey of Existing Mechanisms

Capability signaling in and around OAuth takes five shapes. Registration-time
static declaration in client metadata {{RFC7591}} serves the closed world but
cannot express per-request or per-instance variation and has no analogue where
there is no registration. Authorization server and protected resource metadata
{{RFC8414}} {{RFC9728}} provide extensible server-to-client discovery, but each
extension ordinarily defines its own metadata member. The remaining three are
per-extension: a dedicated request parameter, a dedicated HTTP field, or a
capability implied by construction, as with the presence of a DPoP proof
{{RFC9449}} or the choice of one endpoint over another.

Adjacent protocols generalized where OAuth did not. SIP option tags {{RFC3261}}
pair `Supported` with `Require` over an IANA registry, the closest structural
match. The HTTP `Prefer` field {{RFC7240}} carries `respond-async`, which is
semantically what a deferred-completion parameter reinvents, with
`Preference-Applied` and a registry of its own. Client Hints {{RFC8942}}
contributes the pull-based direction adopted in {{discovery}}. TLS extensions and
HTTP/2 `SETTINGS` take the same form: one negotiation surface, extended by
registry.

GNAP {{RFC9635}} is the instructive case, because it reproduces the asymmetry
from a blank sheet. It names the concept, describing the client instance as
sending "information about the actions the client software can take" and
anticipating "any additional capabilities defined by extensions of this
protocol", and its server-to-client discovery is generic and registry-backed. Its
client-to-server direction is not: capabilities appear per feature, with no
generic field and no vocabulary an extension can register into. A protocol
designed with negotiation as a goal still built the generic surface one way only.

The IANA "OAuth Parameters" registry group currently contains no generic client
capability parameter, field, or registry {{IANA-OAUTH}}.

## Applying the Admission Criterion

The two behaviors in {{existing-drafts}} illustrate the intended use. An
extension adopting this mechanism would also need to state its absent-signal
behavior explicitly. For deferred token response, that behavior is the
synchronous response or error that the server would otherwise return. For a
transaction authorization challenge, it is refusal of the operation without
returning the optional challenge. In each case, removal of the signal suppresses
optional behavior rather than weakening a security check.

Similar-looking behaviors do not necessarily qualify. DPoP nonce enforcement
{{RFC9449}} is one example. If server policy requires a nonce, a capability
signal cannot safely determine whether that requirement is enforced: removing the
signal would otherwise weaken replay protection. Section 11.3 of {{RFC9449}}
requires a server that has provided a nonce not to accept a proof without the
nonce. Nor is the difficulty avoided by framing the signal as permission to rely
on nonces and so to issue longer-lived tokens, because CAP-2 forbids extending
token lifetimes on the basis of a signaled capability however conservative the
fallback appears. Such a requirement is outside this specification's capability
model.

Likewise, a browser fallback such as `redirect_to_web` in
{{FIRST-PARTY-APPS}} would qualify only if an adopting specification defines it
as genuinely optional server behavior and states a safe absent-signal outcome.
If the client behavior can instead be required when server metadata advertises
the feature, server-side discovery is preferable.

The criterion rejects client authentication methods, endpoint selection,
client-initiated request parameters, additive response fields, and behavior a
specification makes mandatory to implement. This is why {{iana-registry}}
records the absent-signal behavior as a registry field rather than leaving the
admission decision implicit.

## Why No Mandatory-to-Understand Semantics

SIP {{RFC3261}} pairs `Supported` with `Require`, letting a client insist an
extension be understood or the request fail. This specification omits the
analogue: `Require` answers a different question, whether the client insists the
server implement something, while a capability states that the client can process
optional server behavior the server remains free not to exercise. Mixing the two
would make some values mandatory and undermine the advisory model. Extensions
needing hard failure define their own error conditions, where removal causes an
availability failure but CAP-1 still rules out weaker security.

## Trade-offs

Three costs are worth stating plainly.

Cache keys become coarser. A protected resource whose responses vary by capability
sends `Vary: OAuth-Client-Capabilities`, keying the cache on the whole list, so an
unrelated capability invalidates entries a per-feature `Vary` would have kept.
Per-feature fields are strictly more precise here. The practical cost is small,
because OAuth-protected responses are authenticated and typically not
shared-cacheable, but the mechanism is genuinely worse on this axis.

Coordination replaces autonomy. Registering a dedicated parameter requires
agreement with no one; a shared registry requires a vocabulary, naming
discipline, and agreement on CAP-1 through CAP-3 as admission criteria.

The count is small. The argument rests on the trend rather than the present
number of extensions. The counter is that a registry is cheaper to establish
before many extensions have shipped incompatible carriers than after, and the two
already in flight have shipped incompatible carriers.

## Open Issues

- Should a server report which capabilities it acted upon, as {{RFC7240}} does
  with `Preference-Applied`? The current answer is no: an OAuth response is
  self-describing, since a client either received a deferred response or did
  not. This should be revisited if implementation experience shows a debugging
  need.
- `OAuth-Client-Capabilities` matches the naming of `OAuth-Client-Attestation`
  {{ABCA}}. `Accept-OAuth-Capabilities` would match the `Accept-*` family. The
  former is preferred here because the field declares client behavior rather
  than performing content negotiation, but this is not settled.
- Whether capability values need versioning within the token, or whether a new
  version registers a new token. The latter is assumed; the `.` and `:`
  characters remain available in the syntax if that changes.
- Whether client software capabilities and running instance capabilities are
  adequately separated by the replacement rule in {{precedence}}, or whether
  instance-level identity mechanisms should carry a capability set of their
  own.

# Acknowledgments
{:numbered="false"}

This work was motivated by {{DTR}} and {{TXN-CHALLENGE}}, whose authors
independently identified the same requirement and whose divergent solutions
made the general problem visible.
