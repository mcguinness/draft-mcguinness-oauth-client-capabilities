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
  RFC9207:
  RFC8942:
  RFC9396:
  RFC9449:
  RFC9635:
  RESOURCE-TOKEN-RESP:
    target: https://datatracker.ietf.org/doc/draft-mcguinness-oauth-resource-token-resp
    title: "Resource Token Response Parameter"
  OAUTH21-VERSIONS-LIST:
    target: https://mailarchive.ietf.org/arch/msg/oauth/hwo5a8eicmWM9q2fUtcVFlYw-HI/
    title: "OAuth 2.0 and 2.1 version support discovery (oauth@ietf.org)"
  OAUTH21-VERSIONS:
    target: https://github.com/oauth-wg/oauth-v2-1/issues/120
    title: "How can an AS support both 2.0 and 2.1 clients concurrently"
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
response to an otherwise ordinary request. A client that cannot process the new
response fails, so the server must know the client's capability before acting.

Two current extensions illustrate the pattern, and disagree on how to carry it.
{{DTR}} requires an authorization server not to defer a response unless the
`completion_mode` request parameter includes `deferred`. {{TXN-CHALLENGE}}
requires a protected resource not to return a transaction authorization
challenge unless `Accept-Txn-Challenge` is true or support is known out of
band.

The requirements are structurally identical. The carriers are not.

## The Carrier Asymmetry {#asymmetry}

Neither carrier can perform the other's function. An HTTP field works for
{{TXN-CHALLENGE}} because the client makes the protected resource request
directly, but that request has no OAuth parameter surface. At the authorization
endpoint, the client constructs a URI for a user agent, which issues the HTTP
request with its own fields; a client-originated field cannot cross that
redirect boundary.

A general mechanism therefore cannot be an HTTP field alone, and cannot be a
request parameter alone. Two request carriers over one shared vocabulary is the
minimum that covers OAuth's actual topology.

## Why Open-World Deployment Makes This Urgent {#open-world}

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

Per-extension signals accumulate in both directions. Each front-channel
capability can enlarge an authorization URI visible to the user agent. Each
resource capability adds a field to protected resource requests; an `Accept-*`
design is one field per feature. A per-extension signal also needs its own
registrations and metadata. A shared vocabulary pays those costs once across
both sides of the asymmetry in {{asymmetry}}.

## What This Specification Does Not Change

This specification defines carriers and a vocabulary. It does not define any
capability values, reserves the `none` sentinel in {{none-value}}, does not
change any existing parameter, and does not require existing extensions to
migrate. It is designed so that extensions may adopt it incrementally.

Two uses are out of scope. Capability values do not carry deployment-local
feature flags or rollout cohort membership, which are server-side policy keyed
on the client's identity rather than properties a client asserts. Nor do they
signal conformance to an existing requirement: a client that violates a MUST is
not made safe by asserting that it does not, and such a client generally cannot
be updated to send the assertion in the first place.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Capability:
: A named behavior that a client asserts it can process and that a server may
  therefore choose to exercise.

Signal:
: The act of a client conveying a capability value to a server through one of
  the carriers defined in {{carriers}}.

Effective capability set:
: The capability set that applies to a request after the carrier and precedence
  rules in {{carriers}} have been applied. Also called the effective set.

Terms not otherwise defined are used as in {{RFC6749}} and {{RFC9110}}.

# Overview {#overview}

A client tells a server what optional behavior it can process by signaling
capability values. A capability value is a short token drawn from a single
registry ({{iana-registry}}), so one vocabulary serves every extension.

Three carriers convey a set, chosen by what the request can hold:

- The `client_capabilities` request parameter, on requests a client makes to an
  authorization server ({{param}}).
- The `OAuth-Client-Capabilities` HTTP field, on requests that carry no OAuth
  parameters, chiefly protected resource requests ({{field}}).
- A `client_capabilities` member in client metadata, supplying a default when a
  request carries no signal ({{metadata}}).

Whichever carrier applies, the result is the request's effective capability
set: the values a server may act upon for that request. A request-level signal
replaces any metadata default rather than adding to it, so a constrained
deployment can retract what its metadata declares ({{precedence}}).

A server advertises the values it recognizes in its own metadata
({{discovery}}). Signaling never obliges a server to act, and the invariants in
{{invariants}} confine what a capability may do, so a signal that is absent,
stripped, or untrue leaves the protocol no weaker.

# Capability Values {#values}

## Syntax

A capability value is a bare token. The syntax uses ABNF {{RFC5234}}, including
its `ALPHA`, `DIGIT`, and `SP` core rules:

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

## Naming Guidance

A capability value names a specific client behavior that a server may exercise
after receiving the value, not a document. `accept-deferred-response` is a
capability; `draft-gerber-oauth-deferred-token-response` is not. A
specification MAY register more than one value where a client can usefully
implement part of it.

A new revision of an extension whose client-side processing differs registers a
new value rather than reusing the old one, so that a server can distinguish the
two. Registering the new value does not retire the old one: its change
controller MAY mark the old value obsolete, and a server MAY continue to
recognize it. A server that recognizes several revisions of a behavior serves
clients built against each of them from a single deployment, which is how
concurrent support for incompatible revisions is achieved.

While an extension is still being revised its client-side processing may change
from one draft to the next, and registering a value per interim revision would
fill the registry with values that never ship. An extension SHOULD register a
value only once the processing it names is stable. Before then implementers can
use an unregistered value, which is safe because a recipient ignores a value it
does not recognize and, under CAP-1, absence of a recognized value leaves the
behavior unexercised.

A revision number is a document reference, so a registered value SHOULD NOT
carry one. Where the revised behavior can be named, name it. Where it cannot,
because a format changed in many small ways at once, a bare sequence suffix is
preferable to a revision number, since it indexes variants rather than pointing
at a document that ceases to be authoritative on publication. An interim value
used before registration MAY carry a revision number, since impermanence is the
point there, but it is replaced by the registered value rather than registered
in that form.

The following non-normative example illustrates the distinction. Suppose an
extension defines a transaction authorization challenge, and a later revision
changes the challenge from a set of form-encoded parameters to a JWT, so that a
client built against the earlier revision cannot parse the later one:

- `txn-challenge` names the original behavior.
- `txn-challenge-jwt` names the revised behavior by what a client must now
  parse, and is the preferred registration.
- `txn-challenge-2` is acceptable where no behavioral name is available.
- `txn-challenge-11` is not, because the suffix names a draft revision rather
  than a behavior, and means nothing once the draft is published.
- `txn-challenge-draft-11` suits the period while the revision is still
  unstable, as an unregistered value that will be replaced rather than
  registered in that form.

A server that recognizes both `txn-challenge` and `txn-challenge-jwt` serves
clients built against either revision from a single deployment.

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

Two consequences follow. Capabilities are self-asserted, so a client claiming
one it lacks can receive a response it cannot process. CAP-2 and CAP-3 keep a
false claim from being accepted as authorization, authentication, or proof of a
security-relevant property, though an extension must still analyze its
operational cost ({{dos}}). And an adversary who removes values degrades the
client to base OAuth, which under CAP-1 is the safe direction at the cost of
optional functionality; see {{security-considerations}}.

These invariants also serve as the admission criterion for the registry; see
{{extension-guidance}}.

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

~~~ http-message
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=SplxlOB...
&client_capabilities=accept-deferred-response
~~~
{: title="A capability signaled on a token request"}

The parameter is not defined for the client registration endpoint. A
registration request carries a JSON body rather than form-encoded parameters,
so a client declares capabilities there using the metadata field in
{{metadata}}.

A client MAY send `client_capabilities` to any authorization server without
prior knowledge of whether the server implements this specification at the
authorization or token endpoint. {{RFC6749}}, Sections 3.1 and 3.2 require an
authorization server to ignore unrecognized request parameters at those
endpoints. Specifications that define its use at another endpoint MUST ensure
that unrecognized request parameters are ignored there. No negotiation
handshake is defined.

The parameter MUST NOT be sent with an empty value. A client that wants an
empty effective set omits the parameter when no metadata default applies and
sends `none` when it needs to override such a default.

Where the parameter would otherwise be carried in the query component of an
authorization request URI, clients SHOULD instead use a pushed authorization
request {{RFC9126}} to bound URI growth and keep the list off the user agent. A
Request Object {{RFC9101}} provides integrity protection, and encryption adds
confidentiality, but passing one by value does not reduce URI size.

## The `OAuth-Client-Capabilities` HTTP Field {#field}

The `OAuth-Client-Capabilities` HTTP field allows a client to signal
capabilities on a request that has no OAuth request parameter surface, most
importantly a protected resource request, which is also where alternative
challenge paths most often coexist; see {{selection}}.

A client MUST NOT use the field on a request at an endpoint where the
`client_capabilities` parameter is defined; it uses {{param}} there instead. An
authorization server MUST ignore the field on any request to such an endpoint.
At the authorization endpoint a user agent issues the HTTP request, so its
fields cannot be attributed to the client. Using only the parameter at
authorization server endpoints also gives each request one unambiguous
effective set, and allows Request Object or pushed-request protections where
those apply.

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
List. The field is invalid if parsing fails, if any member is not a Token Item,
or if any member's Token does not conform to the `capability` production in
{{values}}. The last case is distinct: a Structured Fields Token can be well
formed and still violate that production, as `*bad` does. A recipient MUST
treat an invalid field as absent, matching the treatment of an invalid request
parameter in {{values}}.

A recipient MUST ignore parameters.

The `none` sentinel ({{none-value}}) MUST NOT be sent in this field, and a
recipient MUST ignore a member whose value is `none`.

A server whose response varies with the field MUST include
`OAuth-Client-Capabilities` in the `Vary` field of the response, or use `Vary:
*`, per {{RFC9110}}, Section 12.5.5.

An empty List and an absent field are equivalent: both signal the empty set.

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
denote the empty set. If any element is not a string or does not conform to the
`capability` production, the field is invalid. A recipient MUST NOT derive any
capabilities from an invalid field; the containing metadata protocol determines
whether the document or request is rejected or the field is ignored.

A party publishing or registering this metadata MUST NOT declare a capability
unless every client instance covered by that metadata can process the enabled
behavior, or every less-capable instance will override the default on its
requests. Clients with heterogeneous instances SHOULD omit the metadata field
and signal capabilities on each request.

A client metadata document published at a Client Identifier URL {{CIMD}} is
publicly retrievable, applies uniformly to every deployment using the URL, and
may be cached. Its capabilities are therefore public and shared by every
instance, and changes take effect only as authorization servers refresh their
cached copies. Clients identified this way SHOULD treat the request parameter
in {{param}} as the primary carrier.

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

Request values replace rather than augment metadata so that a less-capable
instance can retract a default. To retract everything, it sends
`client_capabilities=none`.

For a protected resource request, a valid field is the effective set. Without
one, the set is empty, subject to any out-of-band knowledge an extension
defines.

When an authorization request uses a Request Object, the authorization server
MUST determine the request parameter value according to {{RFC9101}}. In
particular, a `client_capabilities` value inside the Request Object takes
precedence over a duplicate value outside it. A capability set in a software
statement is client metadata and remains subject to the request-level override
above; signing the statement does not turn a default into a per-request
declaration.

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

Where a capability is meaningful at more than one endpoint, its registration
({{iana-registry}}) records which endpoints those are.

# Server Behavior {#server-behavior}

Presence of an unrecognized capability value MUST NOT cause a request to fail.

Signaling a capability does not entitle a client to the corresponding behavior.
A server retains discretion over whether to exercise optional behavior.

This specification does not define an error for an absent capability and does
not give any capability mandatory-to-understand semantics. An extension MAY
define an error for a case in which the server cannot proceed without a
particular client-side behavior. Such an error reports the extension's
condition; it does not turn the signal into an authorization input. This
specification defines no analogue of the SIP `Require` field {{RFC3261}}; see
{{rationale}}.

A server SHOULD NOT promote a request-level capability set to durable client
metadata. Client metadata persists according to the mechanism that provides it,
but a subsequent request can override that default with a different set.

## Selecting Among Alternatives {#selection}

A server may have several ways to obtain what a request lacks. For example, a
protected resource might return a transaction authorization challenge, request
step-up authentication, or refuse. The effective capability set can help it
choose a path the client asserts it can complete.

A server MUST determine the assurance a request requires without reference to
the capability set. It MAY use the set to choose among paths that meet that
requirement. If no such path is available, it MUST refuse the request.
Otherwise, removing a value could steer the server to a weaker path,
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

The array MUST NOT contain `none`. If any element is not a string or does not
conform to the `capability` production, the value of this member is invalid and
MUST be ignored in its entirety.

Clients SHOULD signal only capability values that appear in
`client_capabilities_supported`, where the server publishes it. A client MAY
signal values absent from the list, and MAY signal values to a server that
publishes no list at all; a server that does not recognize a value ignores it.
Advertising recognized values lets clients bound request size and
fingerprinting exposure, following the pattern of Client Hints {{RFC8942}}.

Absence of `client_capabilities_supported` does not indicate that the server
fails to support this specification.

Advertising a value is not a commitment to exercise the behavior; see
{{server-behavior}}.

# Guidance for Extension Specifications {#extension-guidance}

An extension that needs a client to signal a processing capability SHOULD
register a value in the registry established in {{iana-registry}} rather than
define a dedicated parameter or field.

The invariants in {{invariants}} decide admission. A value may be justified on
either of two grounds: that a server cannot safely exercise the behavior
without it, or that a server choosing among several paths would otherwise
select one the client cannot complete ({{selection}}). The second requires that
the signal can change whether the operation completes, not merely make an
already-workable path more convenient.

One heuristic catches most misclassifications:

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
  mandatory because the server cannot discover conformance.
- State, in the registration, the carriers and endpoints at which the value is
  meaningful.

Issuer-wide behavior is often the intended design, and coupling it to a
per-issuer metadata flag is a legitimate choice. Where per-client or fractional
rollout is a requirement, however, an extension SHOULD NOT couple the behavior
to such a flag, because it then becomes all-or-nothing for every client of the
issuer; gate it on a capability instead. {{RFC9207}} illustrates the tradeoff
rather than a mistake: coupling the advertisement to a server-wide delivery
commitment is what allows a client to enforce that `iss` is present, and the
cost is that the feature cannot be rolled out per client.

This specification provides no delivery guarantee, and an extension MUST NOT
rely on a capability signal or an advertisement to supply one;
{{server-behavior}} leaves delivery to the server. An extension that needs a
delivery commitment defines it itself, along with how a client learns the
server will honor it.

# Security Considerations {#security-considerations}

The security properties of this mechanism rest on {{invariants}}.

## Signals Are Not Proof

A capability signal asserts, but does not prove, that the client implements the
capability. Depending on their use, transport security, client authentication,
a Request Object, or a signed software statement can authenticate or protect
the assertion without proving it true.

On the front channel, the user agent or another intermediary can modify a bare
request parameter. Injection can produce a response the client cannot process;
removal can deny optional functionality. Under CAP-1 through CAP-3, neither may
weaken security, grant authorization, or skip evidence required by the enabled
behavior.

Servers MUST NOT treat a capability signal as evidence of client identity,
client software version, or client trustworthiness. Where a Request Object
{{RFC9101}} or software statement carries a set, the signature prevents
third-party modification but does not prove implementation. See {{precedence}}.

## Downgrade

Because capability signals may be removed by an adversary, an extension MUST
define a safe absent-signal fallback. If the enabled behavior is how a server
obtains something it requires, the fallback is refusal, not proceeding without
it. Removal costs client functionality, never a server security property.

An extension MUST NOT use a capability to enable a security check that the
server otherwise skips, because removing the signal would remove the check.
Such a check belongs in policy or an authenticated negotiation mechanism.

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

# Privacy Considerations {#privacy-considerations}

A capability set discriminates over the client population and contributes to
fingerprinting. On the front channel it is visible to the user agent, and in a
publicly retrievable client metadata document it is visible to anyone. The
marginal disclosure to an authorization server is smaller, since it already
receives a `client_id` that often identifies the software, but a capability set
can still add information.

Clients that consider their capability set sensitive SHOULD use {{RFC9126}} or
an encrypted Request Object as defined in {{RFC9101}}, SHOULD restrict signaled
values to those advertised in `client_capabilities_supported`, and SHOULD NOT
publish the set in public client metadata. A signed but unencrypted Request
Object provides integrity, not confidentiality.

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

This document registers no capability values. `accept-deferred-response` below
is illustrative, corresponding to a behavior described in {{existing-drafts}}.
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

The same capability on the token request. Because the behavior affects the
token response, the earlier signal does not carry over; see {{signal-scope}}:

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

This appendix is informative and describes how the two extensions that
motivated this work would use the mechanism. Neither is required to migrate.

Deferred Token Response:
: `completion_mode=deferred` becomes `client_capabilities` containing
  `accept-deferred-response`. The authorization server still MUST NOT defer
  unless the value is in the request's effective set. Because deferral affects
  the token response, {{signal-scope}} requires the value in the token request's
  effective set; signaling at an earlier endpoint remains only a hint. The
  proposed single-purpose registry is subsumed by {{iana-registry}}.

Transaction Authorization Challenge:
: `Accept-Txn-Challenge: ?1` becomes `OAuth-Client-Capabilities: txn-challenge`.
  The normative rule and the out-of-band knowledge provision are unchanged. The
  Boolean becomes list membership; absence expresses false.

# Design Rationale {#rationale}

This appendix is informative.

## Survey of Existing Mechanisms

OAuth has static client declarations {{RFC7591}}, extensible server metadata
{{RFC8414}} {{RFC9728}}, and per-extension request parameters, HTTP fields, or
signals implied by construction, such as a DPoP proof {{RFC9449}}. Static
metadata cannot express per-request or per-instance variation, while server
metadata runs only server to client.

Other protocols use shared vocabularies. SIP option tags {{RFC3261}} pair
`Supported` with `Require`; HTTP `Prefer` {{RFC7240}} registers preferences
such as `respond-async`, which is semantically what a deferred-completion
parameter reinvents; and Client Hints {{RFC8942}} lets a server advertise what
it wants sent. GNAP {{RFC9635}} has generic, registry-backed server-to-client
discovery and anticipates "any additional capabilities defined by extensions of
this protocol", yet still represents client-to-server capabilities per feature.

The IANA "OAuth Parameters" registry group currently contains no generic client
capability parameter, field, or registry {{IANA-OAUTH}}.

## Applying the Admission Criterion

The behaviors in {{existing-drafts}} qualify if their registrations state the
safe fallback: a synchronous response or error for deferred response, and
refusal without the optional transaction challenge. Signal removal suppresses
optional behavior without weakening a security check.

Similar-looking behaviors do not necessarily qualify. DPoP nonce enforcement
{{RFC9449}} does not. A removable signal cannot govern a required nonce without
weakening replay protection, and CAP-2 prevents using it to justify
longer-lived tokens. DPoP nonce policy is therefore outside this capability
model.

The `redirect_to_web` fallback in {{FIRST-PARTY-APPS}} qualifies only if
defined as optional server behavior with a safe absent-signal outcome. If
server metadata can instead make the client behavior conditional, discovery is
preferable.

Adding a parameter to a response is almost never a capability. {{RFC6749}},
Sections 4.1.2 and 5.1 already require clients to ignore unrecognized
authorization response parameters and unrecognized token response members, so
delivery is safe for any conforming client and needs no gate.
{{RESOURCE-TOKEN-RESP}} is a near miss of exactly this kind: it returns a
`resource` parameter so a client can confirm which resource its token is valid
for, and what it needs is a way for clients to learn that a server implements
it. That is server metadata, not a client capability.

On gating grounds the criterion also rejects client authentication methods,
endpoint selection, client-initiated parameters, and behavior a specification
makes mandatory to implement.

Selection is the one exception. A behavior safe to issue unconditionally needs
no gating signal, yet can still qualify where a server must choose among paths
and the signal prevents it selecting one the client cannot complete;
{{selection}} governs that narrower case and {{extension-guidance}} bounds it.
{{iana-registry}} records absent-signal behavior to make the test explicit.

## Why No Mandatory-to-Understand Semantics

SIP {{RFC3261}} pairs `Supported` with `Require`, letting a client insist an
extension be understood or the request fail. This specification omits the
analogue: `Require` answers a different question, whether the client insists
the server implement something, while a capability states that the client can
process behavior the server remains free not to exercise. Mixing the two would
undermine the advisory model. Extensions needing hard failure define their own
errors; CAP-1 still prevents removal from weakening security.

## Capabilities and Profile Selection {#profiles}

A related problem is selecting a protocol version or profile rather than a
behavior. Discussion of how an authorization server can serve OAuth 2.0 and 2.1
clients concurrently {{OAUTH21-VERSIONS}} led to a proposal on the working
group list: a per-issuer `oauth_versions_supported` metadata array and a
per-client `oauth_version` registration field. That proposal notes that neither
provides a runtime signal {{OAUTH21-VERSIONS-LIST}}.

That is not capability signaling as defined here. A version names a document
rather than a behavior a server may exercise ({{values}}), and profile
membership is closer to the policy input {{invariants}} excludes. This
specification neither defines it nor proposes that version values be
registered.

A draft revision is a different case, and one this specification does handle.
Where a specification changes what a client must parse between revisions, the
change is a client-side behavior, and {{values}} already covers it: register a
value for the new processing, keep recognizing the old one, and a server serves
both populations at once. No version string is needed, because what a client
signals is the behavior the string stood for, and {{discovery}} lets a client
learn which revisions a server implements without a version at all. What
remains out of scope is selecting a framework version or a profile, where the
label does not correspond to a single client-side behavior.

The two problems do share a carrier shape. That discussion lists a slow rollout
for native applications, whose upgrades reach users gradually, among its
requirements {{OAUTH21-VERSIONS}}. Reading the requirement as a call for a
static default that a single request can override is an inference of this
document rather than a conclusion of that discussion. A registration field
alone cannot provide it: every deployed instance sharing a `client_id` carries
the same declared version, so a rollout staged across native application
releases cannot be expressed. The precedence rule in {{precedence}} is the
general form of that override. Whether framework version selection should reuse
it, or should instead be decomposed into the specific behaviors that actually
need signaling, belongs to that work rather than this one.

## Trade-offs

Cache keys become coarser. A protected resource whose responses vary by
capability sends `Vary: OAuth-Client-Capabilities`, keying the cache on the
whole list. Per-feature fields are more precise, though protected responses are
typically not shared-cacheable.

Coordination replaces autonomy. Registering a dedicated parameter requires no
shared vocabulary; this registry requires naming discipline and agreement on
CAP-1 through CAP-3.

The current extension count is small. The registry anticipates continued growth
and is easier to establish before more incompatible carriers ship.

## Open Issues

- Should a server report which capabilities it acted upon, as {{RFC7240}} does
  with `Preference-Applied`? The current answer is no because the response
  reveals the behavior; implementation experience might show a debugging need.
- `OAuth-Client-Capabilities` matches the naming of `OAuth-Client-Attestation`
  {{ABCA}}. `Accept-OAuth-Capabilities` would match the `Accept-*` family. The
  former is preferred because the field declares client behavior rather than
  negotiating content, but the choice is not settled.
- Whether the `.` and `:` characters the syntax allows should carry any
  structure. {{values}} settles that a revision with different client-side
  processing registers a new value rather than versioning an existing one, so no
  structure is needed today.
- Whether client software capabilities and running instance capabilities are
  adequately separated by the replacement rule in {{precedence}}, or whether
  instance-level identity mechanisms should carry a capability set of their
  own.

# Acknowledgments
{:numbered="false"}

This work was motivated by {{DTR}} and {{TXN-CHALLENGE}}, whose authors
independently identified the same requirement and whose divergent solutions
made the general problem visible.
