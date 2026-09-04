---
title: "Per-Request JWT Signing Algorithm Selection for OAuth 2.0"
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
    organization: University of Wuppertal
    email: "schmieder@uni-wuppertal.de"
 -
    fullname: "Ethan Heilman"
    organization: Cloudflare
    email: "eheilman@cloudflare.com"

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

<!--
OpenID Connect (OIDC) enables a Relying Party (RP) to register an algorithm for securing ID Tokens issued to it.
Additionally, OIDC RP Metadata enables RPs to specify support for multiple algorithms.
However, neither mechanism enables an RP to choose an algorithm to secure an ID Token on a request-by-request basis.
-->
This document introduces the `response_signing_alg` request parameter for the OAuth 2.0 authorization endpoint and the `response_signing_alg_parameter_supported` Authorization Server metadata flag indicating support of that parameter.
The `response_signing_alg` request parameter specifies which algorithm must be used to protect the JWTs that are subsequently obtained by calling the token endpoint.
For Clients dealing with multiple verifying services this improves cryptographic agility when different algorithms are supported among these services.
This can, for example, support smooth transition processes from one algorithm to another such as for the transition towards post-quantum cryptography.

--- middle

# Introduction {#intro}

{{?RFC9964}} introduces JSON Object Signing and Encryption (JOSE) bindings for the three ML-DSA variants standardized by the US NIST in {{FIPS204}}.
This paves the way to use ML-DSA signatures to secure JSON Web Tokens (JWTs).
However, the adoption of ML-DSA is hindered by the need to support verifying services that do not (yet) implement ML-DSA verification.
Consequently, a OAuth Client can decide to handle the migration towards post-quantum security by pushing out the switch to ML-DSA until every service supports ML-DSA.
That causes Clients to remain with RS256 (or potentially other quantum vulnerable signature algorithms) as a primary choice for longer and not offer ML-DSA signed JWTs.

This document introduces a mechanism for relying parties to specify which JSON Web Signature (JWS) algorithm is to be used to secure JWTs in OAuth 2.0 on a request-by-request basis.
Using this mechanism, Clients transitioning towards post-quantum security can begin using post-quantum secure JWTs before every verifying party behind that Client supports a given novel algorithm.

To achieve this, this document introduces the `response_signing_alg` request parameter specifying the JWS algorithm that is to be used to secure the JWT in the token endpoint response.
Additionally, this document specifies the `response_signing_alg_parameter_supported` Authorization Server metadata flag indicating support for the aforementioned request parameter.

While the main motivation of this proposal is the ongoing transition of deployed security mechanisms towards post-quantum secure cryptography, the specified parameter increases the cryptographic agility of OAuth 2.0 in general.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

<!--
This specification uses the terms “Authentication Request”, “ID Token”, “OpenID Provider (OP)”, and “Relying Party (RP)” as defined by OpenID Connect Core 1.0 {{OpenID.Core}}.
-->
This specification uses the terms "JSON Web Signature (JWS)" and "alg Header Parameter" as defined by {{!RFC7515}}, and "JSON Web Token (JWT)" as defined by {{!RFC7519}}.
The terms "Authorization Server", "Authorization Request", and "Client" are used as defined in {{!RFC6749}}.
The JSON Web Algorithms (JWA) specification {{!RFC7518}} defines cryptographic algorithms used with JWS.

# Request Parameter {#sig-alg-param}
When a Authorization Request is constructed the client can opt to include the following parameter using the "application/x-www-form-urlencoded" format, per {{Appendix B of !RFC6749}}:

{:vspace}
`response_signing_alg`
: OPTIONAL. The JWS `alg` value requested for protecting the JWTs in the response of the subsequent token request.

For example, building on the Authorization Request from {{Section 4.1.1 of RFC6749}}, a URI can specify that ML-DSA-44 should be used to secure the JWTs of a subsequent token request as follows (added line breaks are for legibility):

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

# Authorization Server Capability Discovery in Metadata {#sig-alg-param-support}
To go along with the `response_signing_alg` functionality introduced in {{sig-alg-param}}, this document specifies the following Authorization Server metadata parameter:

{:vspace}
`response_signing_alg_parameter_supported`
: OPTIONAL. Boolean value indicating whether the `response_signing_alg` parameter is supported. If nothing is specified, the default value is false.

An Authorization Server that supports the signing algorithm selection parameter MUST include the `response_signing_alg_parameter_supported` with a value of true in its Authorization Server Metadata {{!RFC8414}}.

# Additions to the Request Flow

Before requesting a specific algorithm using the `response_signing_alg` request parameter, a Client SHOULD verify that:

- The `response_signing_alg_parameter_supported` parameter in the Authorization Server's metadata is set to true.
- The Authorization Server supports the specified algorithm, i.e. advertises support in its `token_endpoint_auth_signing_alg_values_supported` list as specified in {{!RFC8414}}.

Upon receipt of an Authorization Request, an Authorization Server supporting the `response_signing_alg` parameter MUST use this choice of algorithm to secure the JWTs in the token response corresponding to the Authorization Request if:

- The `response_signing_alg` parameter exists and contains a valid JWS algorithm.
- The Authorization Server supports the specified algorithm, i.e. advertises support in its `token_endpoint_auth_signing_alg_values_supported` list as specified in {{!RFC8414}}.
- The Client supports the specified algorithm, i.e. advertises support in its `id_token_signing_alg_values_supported` list as specified in {{OpenID.RPMetadataChoices}}.
- The algorithm is permitted for that Client by Authorization Server policy.
- Relevant signing key material is available.

If the `response_signing_alg` parameter is present and any of the aforementioned requirements are not met, the Authorization Server MUST reject the request with the `invalid_request` error as defined in {{Section 4.1.2.1 of RFC6749}} and Section 3.1.2.6 of {{OpenID.Core}}.

If the `response_signing_alg` parameter is not specified, an Authorization Server supporting this parameter MUST proceed with algorithm selection according to existing algorithm selection mechanism.
If the `response_signing_alg` is specified and the aforementioned checks succeed, this choice of algorithm MUST take precedence over other algorithm selection mechanisms for this request.
This includes the `id_token_signed_response_alg` parameter as defined in {{OpenID.Registration}}.
This is an exception to the {{OpenID.Registration}} specification.
It is only valid for this request, does not overwrite the value of the `id_token_signed_response_alg`.

An Authorization Server not supporting the `response_signing_alg` parameter MUST ignore it.

When an Authorization Server accepts a request specifying the `response_signing_alg`, the Authorization Server MUST associate the JWS algorithm with the authorization transaction and the authorization code it returns.
On a subsequent token request, the JWS algorithm associated with the authorization code MUST be used to secure the JWT.

# Security Considerations {#security}

## URI Parameter May Expose Migration Status of Verifying Service
Depending on the usage of the Authorization Request an attacker might be able to deduce which service of an Client verifies the JWT.
A public algorithm choice reveals which algorithm is supported by that service and may indicate which algorithm is not supported.
This may become a problem if a service can be identified that uses insecure cryptography and is subsequently attacked because of it.

TODO: Is this a problem? Parameters can also be specified in other locations e.g. the request body of a POST request, pushed Authorization Requests, etc. That would fix the problem. Should we also specify that?

## Downgrade and Confusion Attacks
If the `response_signing_alg` is transmitted without integrity protection, attackers can delete or modify it.
This potentially results in a downgrade or confusion attack.
To mitigate this, each JWT consuming service MUST keep an algorithm allowlist and reject JWTs secured by algorithms that are not explicitly listed there, as required by Sections 3.1 and 3.2 of {{!RFC8725}}.
Additionally, for every Authorization Request made where the `response_signing_alg` is specified, the algorithm used to secure the JWTs returned on a subsequent token request MUST be checked.
If the algorithm used to secure the JWT is not the previously specified one, the token MUST be rejected.

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
: Boolean value indicating whether the Authorization Server supports the request-by-request signature selection request for Authorization Requests as specified in {{sig-alg-param}} of this document.

Change Controller:
: IESG

Specification Document(s):
: {{sig-alg-param-support}} of this document


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
