---
title: "OPAQUE SASL Mechanism"
category: info

docname: draft-marsiske-sasl-opaque-latest
submissiontype: independent  # also: "IETF", "IAB", or "IRTF"
number:
date:
consensus: false
v: 3
area: "Security"
workgroup: "Simple Authentication and Security Layer"
keyword:
 - SASL
 - Authentication
 - OPAQUE
venue:
  group: "Simple Authentication and Security Layer"
  type: "Working Group"
  mail: "sasl@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/search/?email_list=sasl"
  github: "stef/sasl-opaque"
  latest: "https://stef.github.io/sasl-opaque/draft-marsiske-sasl-opaque.html"

author:
 -
    fullname: Stefan Marsiske
    organization: ctrlc
    email: tfxetjor8@ctrlc.hu

normative:

informative:

  OPAQUE:
    title: The OPAQUE Asymmetric PAKE Protocol
    target: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque

--- abstract

This document describes the OPAQUE{{OPAQUE}} protocol SASL mechanism. OPAQUE is a secure asymmetric password-authenticated key exchange (aPAKE) that supports mutual authentication in a client-server setting without reliance on PKI and with security against pre-computation attacks upon server compromise. This document specifies the messages between a SASL server and client using the OPAQUE protocol for authentication.

--- middle

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Introduction

OPAQUE is an efficient, versatile, modern cryptographic primitive with strong security guarantees that goes beyond what existing SASL mechanisms provide. One of the most important features is that the user's password or anything derived from it is neither exposed to the server nor in the protocol.  Another important security property is that replay attacks are not possible.  OPAQUE can be used can be used over plaintext channels, although the lack of binding between authentication and the rest of the protocol usually form an independent reason to not use that.

# Notation {#notation}

All protocol messages and structures defined in this document use the syntax from {{?RFC8446, Section 3}}.

# Protocol overview

This specification instantiates OPAQUE-3DH with the following configuration tuple ({{OPAQUE}} configurations section): (OPRF(ristretto255, SHA-512), HKDF-SHA-512, HMAC-SHA-512, SHA-512, argon2i(67108864, 2), ristretto255). The sizes of all message components are set accordingly.

The messages closely follow the specification of OPAQUE AKE messsages({{OPAQUE}} AKE messages section), and any field names and calls not defined herein are clarified in that specification.

TODO: Are you going to track changes in the document in the SASL mechanism?

SASL OPAQUE is a client-initiated mechanism. In total 3 messages are neccessary to authenticate the client to the server.

## Client initiates an OPAQUE protocol execution

1. the client queries the authid, the userid and the password. Neither the authid nor the userid can be longer that 65535 bytes in size, TODO:including a null termination character.
2. using the password, the client calls CreateCredentialRequest(), which returns
    - a sensitive context which the client needs to hold on to for the next step of the protocol
    - a credential request.
3. the client-first token sent to the server is the concatenation of the credential request, the userid and authid:

~~~
struct {
    // credential request
    u8 blinded_hashed_to_curve_password[32];
    u8 ephemeral_user_public_key[32];
    u8 user_nonce[32];
    // end of credential request
    u8 userid[]; // utf8 null-terminated
    u8 authid[]; // utf8 null-terminated
} request;
~~~

## Server responds to an OPAQUE credential request

1. the server receives the request from the client.
2. based on the authid and userid the server fetches the user record from its storage backend
3. using the realm or the server FQDN server as the server ID and the userid as the user ID the server calls CreateCredentialResponse(), which returns a credential response, and two sensitive values: the shared key and the user authentication code.
4. the server forms its token by concatenating the credential response from OPAQUE and the null-terminated utf8 encoded realm and sends this to the client.

~~~
struct {
  // credential_response
  u8 evaluated_message[32];
  u8 masking_nonce[32];
  u8 longterm_server_public_key[32];
  u8 envelope_nonce[32];
  u8 envelope_auth_tag[64];
  u8 nonceS[32];
  u8 ephemeral_server_public_key[32];
  u8 auth[64];
  // end of credential response
  u8 realm[]; // utf8 null-terminated.
} response;
~~~

## Client recovers credentials authenticates server

1. The client uses the userid and the realm as the user and the server IDs, the sensitive context from the first step and calls RecoverCredentials().
2. RecoverCredentials() returns a shared key and the authentication code.
3. The client sends the authentication token back to the server.

~~~
struct {
  u8 auth[64];
} client_auth_token;
~~~

## Server authenticates client

1. The Server uses the authentication token calculated during the creation of the credential response, and the authentication token received from the client and calls UserAuth() with them as parameters. If this succeeds, the server considers the channel authenticated, otherwise it signals authentication failed.


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
