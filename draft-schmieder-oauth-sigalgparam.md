---
title: "Per-Request ID Token Signing Algorithm Selection for OpenID Connect"
category: std

docname: draft-schmieder-oauth-sigalgparam-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Web Authorization Protocol"
keyword:
 - Crypto agility
 - Post-Quantum
venue:
  group: "Web Authorization Protocol"
  type: "Working Group"
  mail: "oauth@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/oauth/"
  github: "PhilSchmieder/draft-oauth-sigalg-param"
  latest: "https://PhilSchmieder.github.io/draft-oauth-sigalg-param/draft-schmieder-oauth-sigalgparam.html"

author:
 -
    fullname: "Phil Schmieder"
    organization: Cloudflare
    email: "pschmieder@cloudflare.com"

normative:
  OpenID.Core:
    title: "OpenID Connect Core 1.0 incorporating errata set 2"
    target: https://openid.net/specs/openid-connect-core-1_0.html
    author:
      - name: Nat Sakimura
        ins: N. Sakimura
      - name: John Bradley
        ins: J. Bradley
      - name: Michael B. Jones
        ins: M. B. Jones
      - name: Breno de Medeiros
        ins: B. de Medeiros
      - name: Chuck Mortimore
        ins: C. Mortimore
    date: 2023-12-15
  OpenID.Discovery:
    title: "OpenID Connect Discovery 1.0 incorporating errata set 2"
    target: https://openid.net/specs/openid-connect-discovery-1_0.html
    author:
      - name: Nat Sakimura
        ins: N. Sakimura
      - name: John Bradley
        ins: J. Bradley
      - name: Michael B. Jones
        ins: M. B. Jones
      - name: Edmund Jay
        ins: E. Jay
    date: 2023-12-15
  OpenID.RPMetadataChoices:
    title: "OpenID Connect Relying Party Metadata Choices 1.0"
    target: https://openid.net/specs/openid-connect-rp-metadata-choices-1_0-final.html
    author:
      - name: Michael B. Jones
        ins: M. B. Jones
      - name: Roland Hedberg
        ins: R. Hedberg
      - name: John Bradley
        ins: J. Bradley
      - name: Filip Skokan
        ins: F. Skokan
    date: 2026-03-25
  OpenID.Registration:
    title: "OpenID Connect Dynamic Client Registration 1.0 incorporating errata set 2"
    target: https://openid.net/specs/openid-connect-registration-1_0.html
    author:
      - name: Nat Sakimura
        ins: N. Sakimura
      - name: John Bradley
        ins: J. Bradley
      - name: Michael B. Jones
        ins: M. B. Jones
    date: 2023-12-15

informative:
  FIPS204: DOI.10.6028/NIST.FIPS.204

...

--- abstract

OpenID Connect (OIDC) enables a Relying Party (RP) to register an algorithm for securing ID Tokens issued to it.
Additionally, OIDC RP Metadata enables RPs to specify support for multiple algorithms.
However, neither mechanism enables an RP to choose an algorithm to secure an ID Token on a request-by-request basis.
This document addresses that by introducing the `response_signing_alg` request parameter for the OAuth 2.0 authorization endpoint and the `response_signing_alg_parameter_supported` authorization server metadata flag indicating support of that parameter.
The `response_signing_alg` request parameter specifies which algorithm must be used to protect the ID Token that is subsequently obtained by calling the token endpoint.
For RPs dealing with multiple verifying services this improves cryptographic agility when different algorithms are supported among these services.
This can, for example, support smooth transition processes from one algorithm to another such as for the transition towards post-quantum cryptography.

--- middle

# Introduction {#intro}

{{?RFC9964}} introduces JSON Object Signing and Encryption (JOSE) bindings for the three ML-DSA variants standardized by the US NIST in {{FIPS204}}.
This paves the way to use ML-DSA signatures to secure ID Tokens.
However, the adoption of ML-DSA is hindered by the need to support verifying services that do not (yet) implement ML-DSA verification.
Consequently, a Relying Party (RP) can decide to handle the migration towards post-quantum security by pushing out the switch to ML-DSA until every service supports ML-DSA.
That causes RPs to remain with RS256 (or potentially other quantum vulnerable signature algorithms) as a primary choice for longer and not offer ML-DSA signed tokens.

This document introduces a mechanism for relying parties to specify which JSON Web Signature (JWS) algorithm is to be used to secure the ID Token on a request-by-request basis.
Using this mechanism, RPs transitioning towards post-quantum security can begin using post-quantum secure JWTs before every verifying party behind that RP supports a given novel algorithm.

To achieve this, this document introduces the `response_signing_alg` request parameter specifying the JWS algorithm that is to be used to secure the ID Token in the token endpoint response.
Additionally, this document specifies the `response_signing_alg_parameter_supported` authorization server metadata flag indicating support for the aforementioned request parameter.

While the main motivation of this proposal is the ongoing transition of deployed security mechanisms towards post-quantum secure cryptography, the specified parameter increases the cryptographic agility of OpenID Connect in general.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This specification uses the terms “Authentication Request”, “ID Token”, “OpenID Provider (OP)”, and “Relying Party (RP)” as defined by OpenID Connect Core 1.0 {{OpenID.Core}}.
This specification uses the terms "JSON Web Signature (JWS)" and "alg Header Parameter" as defined by {{!RFC7515}}, and "JSON Web Token (JWT)" as defined by {{!RFC7519}}.
The JSON Web Algorithms (JWA) specification {{!RFC7518}} defines cryptographic algorithms used with JWS.

# Request Parameter {#sig-alg-param}
When a request URI is constructed the client can opt to include the following parameter using the "application/x-www-form-urlencoded" format, per {{Appendix B of !RFC6749}}:

{:vspace}
`response_signing_alg`
: OPTIONAL. The JWS `alg` value requested for protecting the JWT in the response of the subsequent token request.

For example, building on the authorization request from {{Section 4.1.1 of RFC6749}}, a URI can specify that ML-DSA-44 should be used to secure the ID Token of a subsequent token request as follows (added line breaks are for legibility):

~~~ http
GET /authorize
    ?response_type=code
    &client_id=s6BhdRkqt3
    &state=xyz
    &scope=openid
    &response_signing_alg=ML-DSA-44
    &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
Host: server.example.com
~~~

# OP Capability Discovery in Metadata {#sig-alg-param-support}
To go along with the `response_signing_alg` functionality introduced in {{sig-alg-param}}, this document specifies the following OP metadata parameter:

{:vspace}
`response_signing_alg_parameter_supported`
: OPTIONAL. Boolean value indicating whether the `response_signing_alg` parameter is supported. If nothing is specified, the default value is false.

An OP that supports the signing algorithm selection parameter MUST include the `response_signing_alg_parameter_supported` with a value of true in its OpenID Provider Metadata {{OpenID.Discovery}}.

# Additions to the Request Flow

Before requesting a specific algorithm using the `response_signing_alg` request parameter, an RP SHOULD verify that:

- The `response_signing_alg_parameter_supported` parameter in the OP's metadata is set to true.
- The OP (OpenID Connect Provider) supports the specified algorithm, i.e. advertises support in its `id_token_signing_alg_values_supported` list as specified in {{OpenID.Discovery}}.

Upon receipt of an authorization request, an OP supporting the `response_signing_alg` parameter MUST use this choice of algorithm to secure the ID Token in the token response corresponding to the authorization request if:

- The `response_signing_alg` parameter exists and contains a valid JWS algorithm.
- The OP supports the specified algorithm, i.e. advertises support in its `id_token_signing_alg_values_supported` list as specified in {{OpenID.Discovery}}.
- The RP supports the specified algorithm, i.e. advertises support in its `id_token_signing_alg_values_supported` list as specified in {{OpenID.RPMetadataChoices}}.
- The algorithm is permitted for that Client by OP policy.
- Relevant signing key material is available.

If the `response_signing_alg` parameter is present and any of the aforementioned requirements are not met, the OP MUST reject the request with the `invalid_request` error as defined in {{Section 4.1.2.1 of RFC6749}} and Section 3.1.2.6 of {{OpenID.Core}}.

If the `response_signing_alg` parameter is not specified, an OP supporting this parameter MUST proceed with algorithm selection according to existing algorithm selection mechanism.
If the `response_signing_alg` is specified and the aforementioned checks succeed, this choice of algorithm MUST take precedence over other algorithm selection mechanisms for this request.
This includes the `id_token_signed_response_alg` parameter as defined in {{OpenID.Registration}}.
This is an exception to the {{OpenID.Registration}} specification.
It is only valid for this request, does not overwrite the value of the `id_token_signed_response_alg`.

An OP not supporting the `response_signing_alg` parameter MUST ignore it.

When an OP accepts a request specifying the `response_signing_alg`, the OP MUST associate the JWS algorithm with the authorization transaction and the authorization code it returns.
On a subsequent token request, the JWS algorithm associated with the authorization code MUST be used to secure the JWT.

# Security Considerations {#security}

## URI Parameter May Expose Migration Status of Verifying Service
Depending on the usage of the Authorization Request URI an attacker might be able to deduce which service of an RP verifies the ID Token.
A public algorithm choice reveals which algorithm is supported by that service and may indicate which algorithm is not supported.
This may become a problem if a service can be identified that uses insecure cryptography and is subsequently attacked because of it.

TODO: Is this a problem? Parameters can also be specified in other locations e.g. the request body of a POST request, pushed authorization requests, etc. That would fix the problem. Should we also specify that?

## Downgrade and Confusion Attacks
If the `response_signing_alg` is transmitted without integrity protection, attackers can delete or modify it.
This potentially results in a downgrade or confusion attack.
To mitigate this, each ID Token consuming service MUST keep an algorithm allowlist and reject ID Tokens secured by algorithms that are not explicitly listed there, as required by Sections 3.1 and 3.2 of {{!RFC8725}}.
Additionally, for every authorization request made where the `response_signing_alg` is specified, the algorithm used to secure the ID Token returned on a subsequent token request MUST be checked.
If the algorithm used to secure the ID Token is not the previously specified one, the token MUST be rejected.

# IANA Considerations {#iana}

## OAuth 2.0 Parameter Registration

For specification of the `response_signing_alg` request parameter, this document requests registration in the IANA "OAuth Parameters" registry established in {{Section 11.2 of RFC6749}} with:

Parameter name:
: `response_signing_alg`

Parameter usage location:
: Authorization request

Change controller:
: IETF

Specification document:
: {{sig-alg-param}} of this document

## OAuth 2.0 Authorization Server Metadata Registration

For specification of the `response_signing_alg_parameter_supported` metadata parameter, this document requests registration in the "OAuth Authorization Server Metadata" registry for OAuth 2.0 authorization server metadata names established in {{Section 7.1 of !RFC8414}} with:

Metadata Name:
: `response_signing_alg_parameter_supported`

Metadata Description:
: Boolean value indicating whether the OP supports the request-by-request signature selection request for authorization requests as specified in {{sig-alg-param}} of this document.

Change Controller:
: IESG

Specification Document(s):
: {{sig-alg-param-support}} of this document


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
