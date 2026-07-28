# Applying the Admission Test to Existing OAuth Behaviors

Companion analysis to `draft-mcguinness-oauth-client-capabilities`. This is
analysis, not a set of registration requests. The draft registers no capability
values, and nothing here proposes amending another specification. The purpose is
to test whether the admission criterion in the draft actually discriminates, by
running it over behaviors that already exist.

Requirement levels quoted below are from the cited RFC text, verified against
the RFC rather than recalled.

## The result that organizes this

**The admission test is not a property of a feature. It is a property of how an
extension frames what the capability unlocks.**

The same mechanism can pass or fail CAP-1 depending on which side of the
behavior the signal gates. DPoP nonces demonstrate both outcomes, which makes
them the most useful worked example available, and the reason to lead with
them rather than with a spec-by-spec sweep.

So the question to ask of a candidate is not "is this capability-shaped." It is:

> When the signal is absent, what does the server do, and is that the
> conservative direction?

### Worked example: the DPoP nonce

RFC 9449 Section 8: an authorization server "MAY supply a nonce value," and
responds to a request without one with HTTP 400 and `use_dpop_nonce`, supplying
a `DPoP-Nonce` header. On the client side the RFC says only that the client
"will typically retry the request with the new nonce value" and "is expected to
retry." **There is no normative client requirement to implement nonce
handling.**

That makes it capability-shaped on both counts: a conforming DPoP client may
legitimately not implement it, and the authorization server has no way to know
before it challenges. There is no signal for it today.

Now the two framings.

**Framing A: gate the challenge.** *"The authorization server MUST NOT send
`use_dpop_nonce` unless the client signaled nonce support."*

Absent the signal, the server accepts nonce-less proofs. RFC 9449 Section 11.2
is explicit about what nonces buy: "By providing new nonce values at times of
its choosing, the server can limit the lifetime of DPoP proofs, preventing
pre-generated DPoP proofs from being used." So removal of the signal weakens
replay protection. **Violates CAP-1.**

**Framing B: gate the reliance.** *"A client signaling nonce support permits
the authorization server to rely on nonces, and therefore to issue longer-lived
DPoP-bound access tokens."*

Absent the signal, the server follows the guidance RFC 9449 Section 11.2
already gives: "Deployments that do not utilize the nonce mechanism SHOULD NOT
issue long-lived DPoP constrained access tokens, preferring instead to use
short-lived access tokens and refresh tokens." The fallback is a more
conservative issuance posture, and it is the fallback the RFC recommends
independently of any capability mechanism. **Satisfies CAP-1.**

Same mechanism. Opposite verdicts. The difference is entirely in what the
extension says the signal unlocks.

Worth noting that RFC 9449 Section 11.3, "DPoP Nonce Downgrade," already
carries the same instinct at the protocol level: "A server MUST NOT accept any
DPoP proofs without the nonce claim when a DPoP nonce has been provided to the
client." The RFC protects against removal after commitment; CAP-1 generalizes
that to removal before it.

## Tier 1: registry candidates

Capability-shaped, no signal today, and a CAP-1-safe framing exists.

| Behavior the server may exercise | Fallback when the signal is absent | Verdict |
|---|---|---|
| Return a deferred response in place of a token or error ([DTR]) | Ordinary error response, the pre-DTR behavior. No token issued. | Clean |
| Return a transaction authorization challenge ([TXN-CHALLENGE]) | Deny the operation. | Clean in principle; see below |
| Rely on DPoP nonces (RFC 9449, Framing B) | Short-lived access tokens plus refresh, per Section 11.2 | Clean under Framing B only |
| Return `redirect_to_web` at the authorization challenge endpoint ([FIRST-PARTY-APPS]) | Refuse the authorization; see the sweep below | Clean only under the deny framing, which the draft does not state |

Two observations.

DTR is the cleanest case in OAuth. The fallback is not merely conservative, it
is literally the status quo the draft sets out to improve on: an error
response instead of a deferral. Nothing is weakened by removal.

The transaction authorization challenge draft **does not currently state its
fallback.** It says a protected resource "MUST NOT return a transaction
authorization challenge unless" the capability is signaled, but not what the
resource does instead. Denying the operation is the obviously safe reading and
almost certainly the intent, but the draft leaves it unwritten. Under the
draft's Section 10.2 an extension must define a safe absent-signal fallback, so
this is exactly the gap the requirement is meant to catch.

## Tier 2: needs no signal, and why

This tier matters more than tier 1. A registry that admits everything is worth
nothing; the credibility of the mechanism rests on rejecting most candidates.

- **Step-up authentication (RFC 9470).** `insufficient_user_authentication` is
  carried in `WWW-Authenticate` per RFC 6750. A client that does not recognize
  the error code sees a generic 401 and either re-authenticates or fails. It
  degrades gracefully and fails closed, so the resource server can challenge
  unconditionally. No signal needed.
- **Issuer identification (RFC 9207).** The authorization server adds `iss` to
  the authorization response. A client that does not validate it ignores an
  unrecognized parameter. Purely additive. No signal needed.
- **Endpoint selection is already the signal.** Device authorization
  (RFC 8628), pushed authorization requests (RFC 9126), the authorization
  challenge endpoint, token exchange (RFC 8693). Calling the endpoint is proof
  the client implements the flow. A capability value would be redundant with
  the request itself.
- **Client-initiated features.** `authorization_details` (RFC 9396), resource
  indicators (RFC 8707), `response_mode`, and the OpenID Connect `prompt`,
  `display`, and `ui_locales` parameters. The client asks for the behavior; a
  server that responds within what was requested cannot surprise it.
- **Presence is the signal.** The DPoP proof itself (RFC 9449), client
  attestation headers. The artifact's presence proves the capability, which is
  why DPoP needs a capability value for its *nonce* handling and not for DPoP.
- **Mandatory-to-implement conformance.** Anything a specification requires
  clients to support is not a capability; signaling it is redundant. This is
  the test the DPoP nonce passes only because RFC 9449 declined to make client
  nonce handling a MUST. Had it been normative, there would be nothing to
  signal.

## Tier 3: capability-shaped but already served by static client metadata

For these the question is not shape (they are all genuinely "what I can
process") but whether per-request or per-instance variation matters. Mostly it
does not, and the existing static field is the right answer.

- **Response and request encryption.** `id_token_encrypted_response_alg` and
  `_enc`, `userinfo_encrypted_response_alg` and `_enc`,
  `request_object_encryption_alg` and `_enc`; all registered client metadata in
  the IANA OAuth Dynamic Client Registration Metadata registry. These are
  algorithm and key properties of the client software, uniform across
  instances. Static is correct.
- **Logout.** `frontchannel_logout_uri`, `backchannel_logout_uri`,
  `frontchannel_logout_session_required`,
  `backchannel_logout_session_required`; also registered client metadata. These
  carry endpoints, so they are inherently per-registration rather than
  per-request.
- **CIBA token delivery mode.** `backchannel_token_delivery_mode` (poll, ping,
  push) is defined in the CIBA specification as client metadata. Note it is
  *not* in the IANA OAuth Dynamic Client Registration Metadata registry; only
  the server-side `backchannel_token_delivery_modes_supported` appears, in
  authorization server metadata. Ping and push require a client notification
  endpoint, so per-registration is correct here too.

**The boundary case.** Variation matters when a single registered client has
heterogeneous instances, which is precisely the retraction rationale in the
draft's Section 5.5. If a deployment must retract a capability its published
metadata declares, the request parameter exists for that. Whether any given
tier 3 field crosses into tier 1 is a deployment question, not a specification
question, and the draft's replacement semantics answer it without moving the
field.

## CIMD: no capability values, but a carrier that needs care

Taking the direct question first: **CIMD needs no capability value.**

CIMD introduces no new response behavior. The -02 draft does not define new
response fields, error codes, or challenges beyond ordinary OAuth 2.0; the
authorization server fetches metadata from the `client_id` URL and otherwise
runs OAuth unchanged. There is nothing an authorization server might return to
a CIMD-identified client that the client could fail to process, so there is
nothing to gate.

CIMD is also already self-signaling in the tier 2 sense. A `client_id` that is
an `https` URL *is* the declaration that the client speaks CIMD, and the
server-side half is advertised as `client_id_metadata_document_supported` in
authorization server metadata. A capability value would duplicate the
`client_id` itself. CIMD therefore belongs in tier 2.

What is worth attention is CIMD as a *carrier* for other capabilities, where
three of its properties cut against the client metadata field.

- **Public by construction.** The Client Identifier URL "MUST use the `https`
  URL scheme" and any authorization server fetches the document from it.
  Publication is the mechanism, not a deployment choice. The draft's Privacy
  Considerations advise that clients treating their capability set as sensitive
  "SHOULD NOT publish the set in public client metadata"; for a CIMD client that
  advice resolves to "use the request parameter," because the carrier has no
  non-public variant.
- **Uniform across instances by construction.** CIMD does not address
  per-instance variation: each Client Identifier URL is one client identity and
  its metadata applies uniformly to every use of that URL. The draft's
  Section 5.3 already forbids declaring a capability unless every instance
  covered by the metadata can process the enabled behavior, and recommends that
  clients with heterogeneous instances omit the field. For CIMD that is not an
  edge case; it is the default for any software deployed more than once, which
  is the population the draft's Section 1.2 holds up as its motivation. The
  metadata carrier is thus usually the wrong choice for precisely the clients
  that motivate the mechanism.
- **Stale by construction.** An authorization server "MAY cache the client
  metadata" and "SHOULD respect HTTP cache headers ... but MAY define its own
  upper and/or lower bounds on an acceptable cache lifetime as well." A client
  that edits its document cannot know when the change takes effect and cannot
  bound the delay.

None of this breaks anything, because the request parameter is authoritative for
each request. The conclusion is one of emphasis: **for CIMD-identified clients
the request parameter is the primary carrier, and the metadata field is a narrow
optimization**, appropriate only where a capability is non-sensitive and
genuinely universal across every deployment of the software.

## Client attestation: not a capability, and a counter-example worth copying

Attestation-based client authentication ([ABCA]) is not a capability candidate,
for the ordinary reason: it is a client authentication method. It is negotiated
by `token_endpoint_auth_method` on the client side and discovered through
`token_endpoint_auth_methods_supported` containing `attest_jwt_client_auth` on
the server side. Both directions are already covered by existing mechanisms, and
per-request presence of the `OAuth-Client-Attestation` and
`OAuth-Client-Attestation-PoP` fields is self-signaling. Tier 2.

The interesting part is ABCA's **challenge**, because it is the same mechanism
shape as the DPoP nonce (a server-issued freshness value the client must echo
in a proof) and it needs no capability value. ABCA drafted it differently.

| | DPoP nonce (RFC 9449) | ABCA challenge ([ABCA]) |
|---|---|---|
| Server advertises that it uses the mechanism | No; the server challenges reactively | Yes; `challenge_endpoint` in RFC 8414 metadata, which the AS "MUST signal" |
| Client-side requirement | Non-normative: "will typically retry", "is expected to retry" | Normative but conditional: "If the Authorization Server offers a challenge endpoint, the Client MUST retrieve a challenge and MUST use this challenge" |
| Can the server know in advance whether the client will cope? | No | Yes; it published the endpoint, and client conformance follows from that |
| Capability value needed? | Yes, under Framing B | **No** |

Version -10 extends the pattern in two directions that matter here. The
challenge endpoint may now be offered by a resource server as well, advertised
through protected resource metadata (RFC 9728 is registered alongside
RFC 8414 for `challenge_endpoint`), and the conditional client MUST now covers
"the Client Attestation PoP JWT **or DPoP Proof**." So for the
attestation-combined case ABCA is supplying exactly the discoverable-challenge
mechanism RFC 9449 lacks, which both validates the discovery-first rule and
narrows the DPoP nonce candidate, leaving it open for plain DPoP without
attestation rather than for DPoP generally.

ABCA also keeps this coherent for the reactive case: a fresh challenge may
arrive on any response in the `OAuth-Client-Attestation-Challenge` field, and
"The Client MUST use this new Challenge for the next
OAuth-Client-Attestation-PoP." The obligation is normative throughout, so there
is no state in which the server must guess.

**The general rule this yields** is more useful than the capability candidate
itself, because it bounds the registry:

> Server-side discovery plus a conditional client requirement is an alternative
> to a capability signal. Where an extension can express the client-side
> behavior as a MUST conditioned on something the server advertises in its own
> metadata, it should do that instead of registering a capability.

A capability is what remains when the client-side behavior cannot be made
mandatory, because it is genuinely optional for the client on grounds of
platform, cost, or deployment shape, and the server therefore cannot discover
conformance. ABCA could make its challenge mandatory because fetching one is
cheap and universally implementable. RFC 9449 could not take the same route for
nonces, because whether to demand a nonce is a per-request risk decision rather
than a static posture, and advertising it in metadata would not describe the
behavior. That is why the DPoP nonce is a capability candidate and the ABCA
challenge is not.

### Attestation as a carrier for capabilities

The Client Attestation JWT permits extension claims ("The JWT MAY contain
other claims. All claims that are not understood by implementations MUST be
ignored"), so nothing stops an implementer from putting a capability set in one.
The draft's admission test already answers this: a value one would want attested
is not a capability. It is worth stating why, because there is a real argument
on the other side.

The argument for it is granularity. An attestation carries `cnf`, the Client
Instance Key, so it is instance-scoped, and instance-level variation is exactly
what the draft's replacement semantics exist to handle. An instance-scoped
signed carrier looks like the right shape.

It is the right granularity and the wrong lifetime, and the signature buys
nothing. An attestation is minted by an issuer at a point in time and reused
across requests for its validity period, so a capability inside it is immutable
for that window, which defeats retraction, the very thing instance-level
signaling is for. And CAP-3 forbids a server relying on a capability signal
being truthful, so the signature adds no license to trust it. The attestation
issuer is also poorly placed to vouch for a runtime processing property of a
particular invocation. The request parameter provides the same granularity, at
the right lifetime, at lower cost.

## Sweep of active working group drafts

Every active OAuth working group draft, as listed on the datatracker. The
question asked of each is narrow: does it define behavior an authorization
server or resource server returns *to a client* that a non-implementing client
could fail to process, with a client-side requirement weak enough that the
server cannot assume conformance?

The frame is the OAuth *client* specifically. A draft can define plenty of new
behavior between other parties and still be "no" here: `transaction-tokens`, for
example, concerns a resource server calling a token service, which is real
surface but not client-facing.

The `Basis` column records how far the draft was actually read, because the
verdicts are not all equally well-evidenced.

| Draft | New client-facing server behavior? | Verdict | Basis |
|---|---|---|---|
| `attestation-based-client-auth` | Challenge, but with a conditional client MUST and metadata advertisement | No capability needed; see the attestation section | Targeted read at -10 |
| `client-id-metadata-document` | None; an `https` `client_id` self-signals | No | Targeted read at -02 |
| `first-party-apps` | **`redirect_to_web`**, client fallback non-normative, no AS guidance if the client cannot | **Tier 1 candidate**; see below | Targeted read at -04 |
| `refresh-token-expiration` | `refresh_token_timeout`, `authorization_expires_in`; additive, no client MUST to process | No; additive and ignorable | Targeted read at -03 |
| `status-list` | None; token format plus verifier-side status resolution | No | Targeted read at -21 |
| `identity-assertion-authz-grant` | Assertion grant; client-initiated | No | Triage on scope |
| `identity-chaining` | Cross-domain token exchange; client-initiated | No | Triage on scope |
| `rfc7523bis` | JWT client auth and assertion grants; client-initiated | No | Triage on scope |
| `spiffe-client-auth` | Client authentication method | No | Triage on scope |
| `transaction-tokens` | Internal trust-domain exchange; not client-facing | No | Triage on scope |
| `v2-1-15` | Consolidation; removes rather than adds | Not applicable | Triage on scope |
| `security-topics-update` | Best current practice | Not applicable | Triage on scope |
| `browser-based-apps` | Best current practice | Not applicable | Triage on scope |
| `cross-device-security` | Best current practice | Not applicable | Triage on scope |
| `rfc8725bis` | Best current practice | Not applicable | Triage on scope |
| `sd-jwt-vc` | Credential format | Not applicable | Triage on scope |

**One of sixteen** yields a new capability candidate. That ratio is the answer to
"won't you end up registering everything." The mechanism is narrow because the
qualifying conditions are narrow: the behavior has to change what the client
receives, be genuinely optional for the client, and be undiscoverable from
server metadata.

### The candidate: `redirect_to_web`

At the authorization challenge endpoint an authorization server may return
`error: redirect_to_web`, optionally with a `request_uri` and `expires_in`, when
it needs to interact with the user directly: "based on a risk assessment, the
introduction of a new authentication method not supported in the application, or
to handle an exception flow such as account recovery."

The client-side requirement is non-normative: "If no `request_uri` is returned,
the client is expected to initiate a new OAuth Authorization Code flow with
PKCE." And the capability is genuinely optional in a way the earlier examples
are not: a client with no usable browser (a kiosk, a headless deployment, an
autonomous agent with no interactive surface) cannot perform the fallback at
all, however well written it is.

The two framings behave as before:

- **Gate the error.** "The authorization server MUST NOT return
  `redirect_to_web` unless the client signaled browser-fallback support." Absent
  the signal the server must complete authentication in-app regardless, skipping
  the risk-triggered step-up or the new authentication method it had judged
  necessary. **Weaker user authentication. Violates CAP-1.**
- **Gate the escalation, refuse otherwise.** Absent the signal the server
  returns a terminal error: it cannot perform the interaction it requires, so it
  declines to authorize. **Satisfies CAP-1.**

What makes the omission striking is that the error's own definition nearly
forces the safe answer. `redirect_to_web` means "The request is not able to be
fulfilled with any further direct interaction with the user". The server has
already concluded that in-app interaction is insufficient. If it may not send the
error and cannot finish in-app, refusing is the only CAP-1-safe move left. The
draft never says so. Verified against the -04 text: the only client-side
normative statements near `redirect_to_web` concern PKCE, and nothing addresses a
client that cannot reach a browser.

### The systematic finding

Three independent documents now specify the gate and omit the fallback:

- `txn-challenge`: "MUST NOT return a transaction authorization challenge
  unless" signaled, with no statement of what the resource server does instead.
- `first-party-apps`: `redirect_to_web`, with no guidance if the client cannot
  fall back.
- `attestation-based-client-auth` avoided the problem only by making the
  client-side requirement normative and conditioning it on a metadata
  advertisement, which removes the absent case rather than defining it.

This is the strongest available argument for the `Absent-Signal Behavior`
registry field. It is not process overhead: it catches an omission that
extension authors make consistently. Authors specify what the capability turns
*on* and leave what happens when it is *off* implicit, and the implicit answer
is nearly always "proceed without it," which is the CAP-1-violating direction in
both cases above. Requiring the fallback at registration time forces the
question while there is still a designated expert reading the answer.

## What this changes in the draft

Three findings, in descending order of consequence.

1. **The Section 10.2 fallback framing is load-bearing, not editorial.** It is
   the entire difference between Framing A and Framing B above. Stating the
   invariant as "the behavior enabled MUST NOT be necessary to enforce a
   security property" would have excluded the DPoP nonce and the transaction
   challenge both; stating it as "the absent-signal fallback must itself be
   safe" admits both, correctly, and tells an extension author what to write.

2. **Registry entries should record the absent-signal fallback, not only the
   enabled behavior.** CAP-1 is unverifiable at registration time without it,
   and a designated expert cannot apply the criterion to a description that
   says only what the capability turns on. Adding this as a registry field
   makes the invariant checkable rather than aspirational.

3. **Unstated fallbacks are systematic, not incidental.** Three drafts specify
   the gate and omit the absent case; see the sweep. The transaction challenge
   draft's unstated fallback is the first thing the field would have caught, which is a reasonable argument that the
   field belongs in the registry rather than in prose guidance.

Finding 2 is applied to the draft as an `Absent-Signal Behavior` registry
field. Findings 1 and 3 need no change: the former is already the current
wording, and the latter is an observation about another document.

---

[ABCA]: https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth
[DTR]: https://datatracker.ietf.org/doc/draft-gerber-oauth-deferred-token-response
[TXN-CHALLENGE]: https://datatracker.ietf.org/doc/draft-rosomakho-oauth-txn-challenge
[FIRST-PARTY-APPS]: https://datatracker.ietf.org/doc/draft-ietf-oauth-first-party-apps
