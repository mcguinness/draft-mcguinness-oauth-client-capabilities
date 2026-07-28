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
    email: public@karlmcguinness.com

normative:
  RFC6749:
  RFC7591:
  RFC8414:
  RFC9110:
  RFC9651:
  RFC9728:

informative:
  RFC3261:
  RFC7240:
  RFC7636:
  RFC8628:
  RFC8705:
  RFC8942:
  RFC9101:
  RFC9126:
  RFC9396:
  RFC9421:
  RFC9449:
  RFC9470:
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
The client metadata of {{RFC7591}} is already a capability declaration —
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
deployed between parties with a prior arrangement. Two things break as
extensions accumulate against an unbounded client population.

Front-channel accumulation. Every capability relevant before the token request
must ride the authorization request. Deferred completion, transaction
challenge, step-up retry {{RFC9470}}, authorization challenge
{{FIRST-PARTY-APPS}}, DPoP nonce handling {{RFC9449}}, and rich authorization
request processing {{RFC9396}} are six plausible near-term candidates. At that
count the authorization URI carries six separate capability parameters through
a redirect that the user agent can read, log, truncate, and modify, conveying a
six-element set.

Field accumulation. The `Accept-*` family — `Accept`, `Accept-Encoding`,
`Accept-Language`, `Accept-Patch`, and `Accept-Signature` {{RFC9421}} — is one
field per feature by construction, and `Accept-Txn-Challenge` follows it
correctly. Six such extensions means six fields on every protected resource
request for the life of the deployment.

Each per-extension signal also costs, individually, an OAuth Parameters
registration, usually a client metadata registration, usually an authorization
server metadata `*_supported` registration, and sometimes an HTTP field
registration. A shared registry costs one establishment and one value per
extension.

## What This Specification Does Not Change

This specification defines a carrier and a vocabulary. It does not define any
capability value other than the reserved value in {{none-value}}, does not
change any existing parameter, and does not require existing extensions to
migrate. It is designed so that extensions may adopt it incrementally.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Capability:
: A named behavior that a client is able to process, which a server may
  therefore choose to exercise.

Signal:
: The act of a client conveying a capability value to a server through one of
  the carriers defined in {{carriers}}.

Terms not otherwise defined are used as in {{RFC6749}} and {{RFC9110}}.

# Capability Values {#values}

## Syntax

A capability value is a bare token:

~~~ abnf
capability   = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." / ":" )
capabilities = capability *( SP capability )
~~~
{: title="Capability value syntax"}

This character set is deliberately the intersection of two constraints: the
value is valid as a sequence of `NQCHAR` in a form-encoded OAuth parameter
({{RFC6749}}, Appendix A), and valid as an `sf-token` in a structured field
({{RFC9651}}, Section 3.3.4). A single registered value is therefore usable in
both carriers with no transformation.

Capability values are case-sensitive. The order of values is not significant,
and duplicates MUST be ignored.

Capability values MUST NOT carry parameters. An extension that needs structured
detail alongside a capability defines a companion request parameter, or uses
`authorization_details` {{RFC9396}}. The registry is a flat vocabulary.

## Naming Guidance

A capability value names a specific client behavior that a server may rely
upon, not a document. `accept-deferred-response` is a capability;
`draft-gerber-oauth-deferred-token-response` is not. A specification MAY
register more than one value where a client can usefully implement part of it.

A new version of an extension whose client-side processing differs registers a
new value rather than reusing the old one, so that a server can distinguish the
two.

## The `none` Value {#none-value}

The value `none` is reserved. It denotes the empty set: the client signals no
capabilities beyond base OAuth. It exists so that a client can explicitly
retract a statically declared set, as described in {{precedence}}.

`none` MUST NOT appear together with any other capability value. A server that
receives `none` alongside other values MUST treat the signaled set as empty.
Resolving the conflict in favor of the empty set rather than rejecting the
request keeps the semantics of a capability signal non-fatal, consistent with
{{server-behavior}}, and errs toward the direction CAP-1 makes safe. The only
condition under which this specification has a server reject a request on
account of the signal is the resource guard in {{dos}}.

# Capability Invariants {#invariants}

The following two constraints apply to every registered capability value and to
every use of the carriers in {{carriers}}. They are the basis on which the
security analysis in {{security-considerations}} rests, and they are normative.

CAP-1:
: A capability MUST only enable optional server behavior. Removing a capability
  value from a request MUST NOT cause a server to apply weaker client
  authentication, weaker sender constraining, weaker user authentication, or a
  more permissive policy than it would have applied had the value never been
  defined. Absence MUST be safe.

CAP-2:
: A capability MUST NOT be an input to an authorization decision. A capability
  describes what a client is able to process, not what a client is permitted to
  obtain. Servers MUST NOT grant scope, relax consent requirements, or extend
  token lifetimes on the basis of a signaled capability.

Two consequences follow.

Capabilities are self-asserted, and this is sufficient. A client that claims a
capability it does not have receives a response it cannot process, which harms
only itself. CAP-1 and CAP-2 ensure that a false claim cannot escalate
privilege, weaken a security property, or affect another party. No
authentication of the signal is required, and none is defined.

Stripping is a functionality attack, not a security attack. An adversary able
to modify a request — including the user agent, on the front channel — can
remove capability values and degrade the client to base OAuth. Under CAP-1 that
is by construction the safe direction.

These invariants also serve as the admission criterion for the registry; see
{{extension-guidance}}.

# Carriers {#carriers}

## The `client_capabilities` Request Parameter {#param}

client_capabilities:
: OPTIONAL. A space-delimited list of capability values, as defined in
  {{values}}.

The parameter is defined for use at the authorization endpoint, the token
endpoint, the pushed authorization request endpoint {{RFC9126}}, the device
authorization endpoint {{RFC8628}}, and the authorization challenge endpoint
{{FIRST-PARTY-APPS}}. It MAY appear inside a request object {{RFC9101}}. An
extension registering a capability value states the endpoints at which the
value is meaningful.

The parameter is not defined for the client registration endpoint. A
registration request carries a JSON body rather than form-encoded parameters,
so a client declares capabilities there using the metadata field in
{{metadata}}.

A client MAY send `client_capabilities` to any authorization server without
prior knowledge of whether the server implements this specification.
{{RFC6749}}, Sections 3.1 and 3.2 require that "the authorization server MUST
ignore unrecognized request parameters", so the parameter is safe to send
unconditionally. Whether a server acted on the signal is revealed by the
server's behavior, which is what an advisory signal requires. No negotiation
handshake is needed and none is defined.

The parameter MUST NOT be sent with an empty value; a client with no
capabilities to signal either omits the parameter or sends `none`.

Where the parameter would otherwise be carried in the query component of an
authorization request URI, clients SHOULD instead use a pushed authorization
request {{RFC9126}} or a request object {{RFC9101}}. This bounds the growth of
the authorization URI and keeps the capability list off the user agent. It is a
SHOULD rather than a MUST because CAP-1 makes query carriage safe, if
undesirable.

## The `OAuth-Client-Capabilities` HTTP Field {#field}

The `OAuth-Client-Capabilities` HTTP field allows a client to signal
capabilities on a request that has no OAuth request parameter surface, most
importantly a protected resource request.

Its value is a List of Tokens ({{RFC9651}}, Section 3.1), where each member is
a capability value as defined in {{values}}:

~~~ http-message
GET /transfers/42 HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGci...
OAuth-Client-Capabilities: txn-challenge
~~~
{: title="Signaling a capability on a protected resource request"}

Members MUST NOT carry structured field parameters. A recipient MUST ignore any
member it does not recognize, and MUST ignore any parameters present.

A server whose response varies with the field MUST include
`OAuth-Client-Capabilities` in the `Vary` field of the response, per
{{RFC9110}}, Section 12.5.5.

The field MAY also be used on a direct client-to-server request to an OAuth
endpoint, but a client that can set a request parameter SHOULD use {{param}}
rather than the field, so that the signal is covered by any signature over the
request.

A client MUST NOT send both the field and the `client_capabilities` parameter
on the same request. If a server receives both, the parameter is authoritative
and the field MUST be ignored, so that the carrier which can be
integrity-protected wins.

## Client Metadata Declaration {#metadata}

client_capabilities:
: OPTIONAL. A JSON array of strings, each a capability value as defined in
  {{values}}, describing the capabilities of the client software.

This is a client metadata field as defined in {{RFC7591}}, Section 2. One
definition covers three cases: metadata registered with an authorization
server, a client metadata document published at the client's identifier
{{CIMD}}, and metadata carried in a software statement.

The metadata field describes the client software. It cannot describe a
particular deployment or running instance of that software, which may be more
constrained; see {{precedence}}.

The array MUST NOT contain `none`; an absent field and an empty array both
denote the empty set.

## Scope of a Signal {#signal-scope}

A capability signal applies to the request that carries it. It does not
establish a property of the client that persists across the several requests of
a grant.

This matters most where the behavior a capability enables occurs at a different
endpoint from the one at which a client first signals it. A client that signals
a capability in a pushed authorization request has signaled it for the
authorization request that the resulting `request_uri` stands in for, and for
nothing else. Where the capability governs behavior at the token endpoint, the
client MUST signal it again on the token request, and the authorization server
MUST NOT infer it from an earlier request in the same grant.

A concrete instance: an extension that permits the authorization server to
return a deferred response instead of an access token affects the token
response, so the capability must be present on the token request. Signaling it
only through a pushed authorization request is not sufficient, and an extension
whose capability behaves this way states so.

The token request is a direct back-channel request, so the front-channel
concerns described in {{param}} do not apply to it and repeating the signal
there costs nothing.

Where a capability is meaningful at more than one endpoint, its registration
({{iana-registry}}) records which endpoints those are.

## Precedence {#precedence}

When `client_capabilities` is present as a request parameter, it is
authoritative for that request and replaces any set declared in client
metadata. When it is absent, the set declared in client metadata applies, if
any.

The rule is replacement rather than union because retraction is a requirement.
A client whose registered metadata declares a capability may have a deployment
that does not possess it — a command-line client running in a batch job cannot
return in six hours to collect a deferred response, whatever its published
metadata says. Under union semantics such a deployment could never say so. To
retract everything, a client sends `client_capabilities=none`.

This rule applies only to carriers directed at an authorization server. It does
not apply to {{field}}: a protected resource holds an access token, not the
client's registered metadata, and generally has nothing to replace. On a
request bearing the field, the field is the signaled set. On a request without
it, no capabilities are signaled, subject to any out-of-band knowledge
provision an individual extension defines.

Where a capability set is carried in a signed structure — a request object
{{RFC9101}} or a software statement — and also as a bare request parameter, the
signed value takes precedence.

# Server Behavior {#server-behavior}

A server MUST ignore capability values it does not recognize. Presence of an
unrecognized value MUST NOT cause a request to fail.

Signaling a capability does not entitle a client to the corresponding behavior.
A server retains full discretion over whether to exercise any optional
behavior, on the basis of policy, risk assessment, or operational state.

A server MUST NOT reject a request solely because a capability it would have
preferred is absent. Where an extension genuinely requires a client-side
behavior in order to proceed, the extension defines its own error response for
that condition; this specification defines no mandatory-to-understand semantics
and no analogue of the SIP `Require` field {{RFC3261}}. See {{rationale}}.

A server SHOULD NOT record a signaled capability set as durable state
associated with the client. Capabilities describe a request, and a subsequent
request may signal a different set.

# Discovery {#discovery}

client_capabilities_supported:
: OPTIONAL. A JSON array of strings containing the capability values that the
  server recognizes and may act upon.

The field is defined for authorization server metadata {{RFC8414}} and for
protected resource metadata {{RFC9728}}.

The direction here is deliberate and follows Client Hints {{RFC8942}}, in which
a server advertises which hints it wants and a client sends only those. A
client that supports fourteen capabilities, talking to a server that advertises
two, signals two. This bounds front-channel growth ({{open-world}}) and limits
the fingerprinting surface ({{privacy-considerations}}).

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
equivalent signed structure. Capabilities are unauthenticated by design, and
CAP-1 and CAP-2 are what make that acceptable. An extension that finds itself
wanting to bind a capability to a key, or to trust it in a policy decision, has
misclassified it.

Two further points of discipline:

- Register a behavior, not a specification. See {{values}}.
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
: These describe which flows a client is permitted to use, and are enforced by
  the authorization server. A capability describes what a client is able to
  process. The distinction is permission versus ability.

Authorization server metadata:
: {{RFC8414}} and {{RFC9728}} are the server-to-client direction of the same
  problem and are already fully generic. This specification supplies the
  client-to-server direction, which has no existing generic form.

Client attestation:
: See {{extension-guidance}}. The two mechanisms are complementary and address
  different questions: what the client can do, versus what can be proven about
  the client.

# Security Considerations {#security-considerations}

The security properties of this mechanism rest on {{invariants}}, which are
stated normatively rather than here because they constrain the registry rather
than any single deployment. This section describes what follows from them.

## Signals Are Unauthenticated

A capability signal is an unauthenticated client assertion. On the front
channel it is also modifiable by the user agent and by anything on the redirect
path. This specification defines no integrity protection for the signal, and
none is required: CAP-1 confines the effect of any capability to enabling
optional behavior, so injection of a value can at worst cause a server to send
a response the client cannot process, and removal can at worst deny the client
an optional behavior. Neither outcome weakens a security property of the
protocol.

Servers MUST NOT treat a capability signal as evidence of client identity,
client software version, or client trustworthiness.

## Downgrade

Because capability signals may be removed by an adversary, an extension MUST
NOT be designed such that removal is the attacker's goal. Concretely: the
behavior enabled by a capability MUST NOT be the behavior that enforces a
security property. An extension that would like to say "the client can perform
a stronger check, so enable it" has inverted the requirement; the stronger
check belongs in policy, negotiated through mechanisms that are authenticated.

## Denial of Service {#dos}

A capability list is attacker-controllable in size. Servers MUST bound the
number of values and the total length they will parse, and MUST reject
oversized values with `invalid_request` rather than allocating proportionally.
Because unrecognized values are ignored rather than looked up transitively,
parsing cost is linear in input size.

## Interaction with Signed Requests

Where a request object {{RFC9101}} or software statement carries a capability
set, that set is integrity-protected and the precedence rule in {{precedence}}
prefers it. This does not make the values more trustworthy in the sense of
CAP-2 — a signature attests that the client said it, not that it is true — but
it does prevent third-party modification.

# Privacy Considerations {#privacy-considerations}

A capability set is a discriminator over the client population and contributes
to fingerprinting. On the front channel it is visible to the user agent.

Three factors bound the exposure. A capability set is a property of the client
software, which the `client_id` already identifies to the authorization server,
so the marginal information disclosed to that server is small. The discovery
mechanism in {{discovery}} lets a client send only values the server will act
upon, rather than its full set. And the recommendation in {{param}} to carry
the parameter via a pushed authorization request or request object keeps the
set out of the user agent entirely.

Clients that consider their capability set sensitive SHOULD use
{{RFC9126}} or {{RFC9101}} and SHOULD restrict signaled values to those
advertised in `client_capabilities_supported`.

Capability values MUST NOT encode information about the end user, the device,
or the deployment environment. Such values would not satisfy CAP-2 in any case,
since they describe neither an ability nor a behavior.

# IANA Considerations

## OAuth Client Capabilities Registry {#iana-registry}

This specification requests that IANA establish an "OAuth Client Capabilities"
registry in the "OAuth Parameters" registry group. Values are registered on a
Specification Required basis.

The registry contains the following fields:

Capability Value:
: The token, conforming to the `capability` production in {{values}}.

Description:
: A brief description of the client behavior a server may rely upon.

Carriers:
: The carriers in which the value is meaningful: any of "request parameter",
  "HTTP field", "client metadata".

Endpoints:
: The endpoints or request types at which the value is meaningful, where
  applicable.

Change Controller:
: For values defined in IETF stream documents, the IESG. Otherwise, the party
  responsible for the registration.

Specification Document(s):
: A reference to the document defining the value.

Designated experts evaluating a registration request should confirm that the
proposed value satisfies CAP-1 and CAP-2 in {{invariants}}, and should apply
the criterion in {{extension-guidance}}.

The registry's initial content is:

Capability Value:
: `none`

Description:
: Reserved. Denotes the empty capability set.

Carriers:
: request parameter

Endpoints:
: Any

Change Controller:
: IESG

Specification Document(s):
: This specification, {{none-value}}

## OAuth Parameters Registry

This specification requests registration of the following value in the IANA
"OAuth Parameters" registry established by {{RFC6749}}:

Parameter Name:
: `client_capabilities`

Parameter Usage Location:
: authorization request, token request, pushed authorization request, device
  authorization request, authorization challenge request

Change Controller:
: IESG

Specification Document(s):
: This specification, {{param}}

## OAuth Dynamic Client Registration Metadata Registry

This specification requests registration of the following value in the IANA
"OAuth Dynamic Client Registration Metadata" registry established by
{{RFC7591}}:

Client Metadata Name:
: `client_capabilities`

Client Metadata Description:
: Capability values describing behaviors the client software is able to process

Change Controller:
: IESG

Specification Document(s):
: This specification, {{metadata}}

## OAuth Authorization Server Metadata Registry

This specification requests registration of the following value in the IANA
"OAuth Authorization Server Metadata" registry established by {{RFC8414}}:

Metadata Name:
: `client_capabilities_supported`

Metadata Description:
: Capability values the authorization server recognizes and may act upon

Change Controller:
: IESG

Specification Document(s):
: This specification, {{discovery}}

## OAuth Protected Resource Metadata Registry

This specification requests registration of the following value in the IANA
"OAuth Protected Resource Metadata" registry established by {{RFC9728}}:

Metadata Name:
: `client_capabilities_supported`

Metadata Description:
: Capability values the protected resource recognizes and may act upon

Change Controller:
: IESG

Specification Document(s):
: This specification, {{discovery}}

## HTTP Field Name Registry

This specification requests registration of the following value in the "HTTP
Field Name" registry:

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

This document registers no capability value other than `none`. The values
`accept-deferred-response` and `txn-challenge` appearing below are illustrative,
and correspond to the behaviors described in {{existing-drafts}}.

Authorization server metadata advertising what the server will act upon:

~~~ json
{
  "issuer": "https://as.example.com",
  "client_capabilities_supported": ["accept-deferred-response"]
}
~~~
{: title="Server-side advertisement"}

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

The same capability repeated on the token request. Because the behavior it
enables affects the token response, the earlier signal does not carry over; see
{{signal-scope}}:

~~~ http-message
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=SplxlOB...
&client_id=https%3A%2F%2Fapp.example%2Fclient
&client_capabilities=accept-deferred-response
~~~
{: title="Signaling at the endpoint where the behavior occurs"}

A different deployment of the same client software, whose published metadata
declares `accept-deferred-response`, retracting it because this process cannot
outlive the request:

~~~ http-message
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=SplxlOB...
&client_id=https%3A%2F%2Fapp.example%2Fclient
&client_capabilities=none
~~~
{: title="Explicit retraction by a constrained deployment"}

Client metadata declaring the software-level set, spanning both carriers:

~~~ json
{
  "client_id": "https://app.example/client",
  "client_capabilities": ["accept-deferred-response", "txn-challenge"]
}
~~~
{: title="Static declaration in client metadata"}

# Applying This Specification to Existing Drafts {#existing-drafts}

This appendix is informative and describes how the two extensions that motivated
this work would use the mechanism. Neither is required to migrate.

Deferred Token Response:
: `completion_mode=deferred` becomes `client_capabilities` containing
  `accept-deferred-response`. The normative rule is unchanged in shape: the
  authorization server MUST NOT defer a response unless the request signals the
  capability. The "OAuth Completion Mode Values" registry proposed by {{DTR}}
  becomes unnecessary, being a single-value registry subsumed by
  {{iana-registry}}. The draft's hint at the authorization, device
  authorization, and authorization challenge endpoints becomes ordinary
  front-channel carriage and inherits the recommendation in {{param}} to use a
  pushed authorization request or request object. Because deferral occurs in
  the token response, {{signal-scope}} requires the capability to be present on
  the token request itself; this matches the draft's existing rule that the
  client "signals opt-in to DTR by including `deferred` among the
  `completion_mode` values on the originating grant's token endpoint request",
  with the preceding-endpoint occurrence remaining an optional hint.

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

Capability signaling in and around OAuth falls into six shapes. Organizing by
shape rather than by specification makes the gap visible.

- Registration-time static declaration, client to server, once. {{RFC7591}}
  client metadata: `grant_types`, `response_types`,
  `token_endpoint_auth_method`, `require_signed_request_object` {{RFC9101}},
  `require_pushed_authorization_requests` {{RFC9126}},
  `tls_client_certificate_bound_access_tokens` {{RFC8705}},
  `dpop_bound_access_tokens` {{RFC9449}}. Serves the closed world well. Cannot
  express per-request or per-instance variation, and has no analogue where
  there is no registration.

- Server-to-client discovery. {{RFC8414}} and {{RFC9728}}, with `*_supported`
  arrays throughout. Fully generic and fully solved — in one direction only.

- Per-extension request parameter. `prompt`, `claims`, `acr_values`, `max_age`
  {{OIDC}}; `code_challenge_method` {{RFC7636}}; `dpop_jkt` {{RFC9449}};
  `completion_mode` {{DTR}}.

- Per-extension HTTP field, or capability implied by construction. `DPoP`
  {{RFC9449}}, where presence is the signal; `OAuth-Client-Attestation`
  {{ABCA}}; `Accept-Txn-Challenge` {{TXN-CHALLENGE}}; and endpoint selection
  itself, as with the device authorization endpoint {{RFC8628}} or the
  authorization challenge endpoint {{FIRST-PARTY-APPS}}.

- Generic mechanisms in adjacent protocols, none adopted by OAuth. SIP option
  tags {{RFC3261}}, with `Supported`, `Require`, `Unsupported`, and an IANA
  registry — the closest structural match. The HTTP `Prefer` field {{RFC7240}},
  whose `respond-async` preference is semantically what
  `completion_mode=deferred` reinvented, together with `Preference-Applied` and
  an IANA registry. Client Hints {{RFC8942}}, notable for its pull-based
  direction. TLS extensions, HTTP/2 and QUIC `SETTINGS`, and SASL mechanism
  lists all take the same form: one negotiation surface, extended by registry.

- GNAP. {{RFC9635}} reproduces the same asymmetry from a blank sheet, which is
  the most instructive data point available. GNAP names the concept
  explicitly, describing the client instance as sending "information about the
  actions the client software can take", and anticipates "any additional
  capabilities defined by extensions of this protocol" ({{RFC9635}}, Section
  4). Its server-to-client direction is generic and registry-backed: AS
  discovery ({{RFC9635}}, Section 9) returns `key_proofs_supported`,
  `sub_id_formats_supported`,
  `assertion_formats_supported`, and `key_rotation_supported`, extensible
  through the "GNAP Authorization Server Discovery Fields" registry. Its
  client-to-server direction is not: capabilities are realized per feature, as
  `interact.start`, `interact.finish`, `subject.sub_id_formats`, and
  `subject.assertion_formats`, with no generic field and no capability
  vocabulary an extension can register into. A protocol designed with
  negotiation as a stated goal still built the generic surface in one direction
  only.

A review of the thirteen sub-registries in the IANA "OAuth Parameters" registry
group finds no generic client capability parameter, field, or registry.

## Why No Mandatory-to-Understand Semantics

The closest precedent, SIP {{RFC3261}}, pairs `Supported` with `Require`, so
that a client can insist an extension be understood or the request fail. This
specification deliberately omits the analogue.

`Require` semantics create precisely the downgrade surface that CAP-1 exists to
eliminate: a value whose removal changes whether a request succeeds is a value
an adversary has a reason to remove, and a value a server has a reason to
trust. Extensions that genuinely need hard failure already express it through
their own error responses, where the failure condition can be specified
precisely.

## Trade-offs

Three costs are worth stating plainly.

Cache keys become coarser. A protected resource whose responses vary by
capability sends `Vary: OAuth-Client-Capabilities`, which keys the cache on the
entire list; adding an unrelated capability invalidates entries that a
per-feature `Vary: Accept-Txn-Challenge` would have preserved. Per-feature
fields are strictly more precise on this axis. The practical cost is small,
because OAuth-protected responses are authenticated and typically not shared-
cacheable, but the mechanism is genuinely worse here and does not offer a
caching benefit.

Coordination replaces autonomy. Registering a dedicated parameter requires
agreement with no one. A shared registry requires a shared vocabulary, naming
discipline, and agreement on CAP-1 and CAP-2 as admission criteria. That is
overhead paid up front against savings realized later.

The count is currently two. The argument rests on the trend rather than the
present number of extensions. The counter-argument is that a registry is far
cheaper to establish before ten extensions have shipped incompatible carriers
than afterward, and that the two extensions already in flight have shipped
incompatible carriers.

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
