# OAuth 2.0 Client Capabilities

This is the working area for the individual Internet-Draft, "OAuth 2.0 Client Capabilities".

OAuth extensions increasingly need the server to know, before it acts, whether the client can process a new protocol behavior. Extensions define that signal individually today, and the two carriers in use are not interchangeable: the front channel is browser-mediated and cannot carry a client-originated HTTP field, while a protected resource request has no OAuth parameter surface. This specification defines one registry of capability values and three carriers for them (a `client_capabilities` request parameter, an `OAuth-Client-Capabilities` HTTP field, and a `client_capabilities` client metadata field), constrained so that a capability may only enable optional server behavior and its absence is always safe.

* [Editor's Copy (HTML)](https://mcguinness.github.io/draft-mcguinness-oauth-client-capabilities/draft-mcguinness-oauth-client-capabilities.html)
* [Editor's Copy (TXT)](https://mcguinness.github.io/draft-mcguinness-oauth-client-capabilities/draft-mcguinness-oauth-client-capabilities.txt)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-client-capabilities/) (after first submission)

## Companion Analysis

* [Applying the Admission Test to Existing OAuth Behaviors](AUDIT.md): runs the draft's admission criterion over existing specs. Finds that admissibility turns on framing but that framing alone is not enough: a candidate can satisfy CAP-1 and still be barred by CAP-2. DPoP nonce enforcement fails at both steps and is outside the model. Also separates gating from selection: a behavior can be safe to issue unconditionally and still warrant a signal, so that a resource server choosing among challenge paths does not pick one the client cannot complete. Most candidates surveyed need no capability at all.

## Motivating Drafts

Both define the same normative shape with different carriers. Either could adopt this mechanism; neither is required to.

* [Deferred Token Response](https://datatracker.ietf.org/doc/draft-gerber-oauth-deferred-token-response/): `completion_mode=deferred` request parameter
* [Transaction Authorization Challenge](https://datatracker.ietf.org/doc/draft-rosomakho-oauth-txn-challenge/): `Accept-Txn-Challenge: ?1` HTTP field

## Related Drafts

* [OAuth Client ID Metadata Document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/) (open-world client identification; the static declaration carrier)
* [OAuth 2.0 Software Statement Issuance](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-software-statement-issuance/) (signed client metadata carrier)
* [OAuth 2.0 Client Instance Assertion](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-client-instance-assertion/) (instance layer; see the open issue on software-vs-instance capability sets)

## Contributing

See the [guidelines for contributions](CONTRIBUTING.md).

Contributions can be made by creating pull requests. The GitHub interface supports creating pull requests using the Edit (✏) button.

## Command Line Usage

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

Command line usage requires that you have the necessary software installed. See [the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).
