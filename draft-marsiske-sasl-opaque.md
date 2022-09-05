RVR: Relative to 3659ed8fbf6cccec1d547f7ae6aef89e948ab0b0
---
title: "OPAQUE SASL Mechanism"
category: info

docname: draft-marsiske-sasl-opaque-latest
submissiontype: IETF  # also: "independent", "IAB", or "IRTF"
number:
date:
consensus: true
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

RVR: "IETF" is the heaviest process, you may want to go for an "independent" submission (but the Kitten WG may choose to adopt your spec and turn it into "IETF", and you could pitch for that)

RVR: What looks like an API call has a formal definition; make a concise reference.

This document describes the OPAQUE{{OPAQUE}} protocol SASL mechanism. OPAQUE is a secure asymmetric password-authenticated key exchange (aPAKE) that supports mutual authentication in a client-server setting without reliance on PKI and with security against pre-computation attacks upon server compromise. This document specifies the messages between a SASL server and client using the OPAQUE protocol for authentication.

RVR: Maybe mention "SASL" or "SASL Mechanism" in the title?

--- middle

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Introduction

OPAQUE is an efficient, versatile, modern cryptographic primitive with strong security guarantees that goes beyond what existing SASL mechanisms provide. One of the most important features is that the users password or anything derived from it is never exposed to the server. Another important security property is that replay attacks are also not possible.

RVR: users password --> user's password

RVR: another / also

RVR: Not sure if a broad comparison with existing SASL mechanisms adds much.  I don't suppose it would make people quibbble, but plainly stating goals and properties yields more clarity.

RVR: "versatile", "modern" and "[most] important" are subjective words that add very little.

# Notation {#notation}

All protocol messages and structures defined in this document use the syntax from {{?RFC8446, Section 3}}.

# Protocol overview

RVR: Need an accurate reference for "3DH" and the meaning of the tuple (the one you said was just Informative)

This specification instantiates OPAQUE-3DH with the following configuration tuple ({{OPAQUE}} configurations section): (OPRF(ristretto255, SHA-512), HKDF-SHA-512, HMAC-SHA-512, SHA-512, argon2i(67108864, 2), ristretto255). The sizes of all message components are set accordingly.

The messages closely follow the specification of OPAQUE AKE messsages({{OPAQUE}} AKE messages section).

SASL OPAQUE is a client initiated mechanism. In total 3 messages are neccessary to authenticate the client to the server.

RVR: client initiated --> client-initiated

RVR: "3 messages" --> "2 token exchanges"

## Client initiates an OPAQUE protocol execution

RVR: "authid" can be mistaken for "authnid" so I would suggest "authzid" (or a reference)
RVR: Suggest to write out 64KB as 65536 (or 65535 or 64000) bytes

RVR: "CreateCredentialRequest()" looks like an API call; turn it into an accurate Normative reference with well-defined input/output parameter connections.

RVR: "hold onto" --> "hold on to"

RVR: the structure looks clear enough.  you do not *need* a NUL in the last byte, because you can derive the SASL token length from the context.

1. the client queries the authid, the userid and the password. Neither the authid nor the userid can be longer that 64KB in size.
2. using the password the client calls CreateCredentialRequest() this returns
    - a sensitive context which the client needs to hold onto for the next step of the protocol
    - a credential request.
3. the request to be sent to the server is the concatenation of the credential request, the userid and authid:

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

RVR: Different format from "request { ... }" like below

RVR: Fixed sizes like "32" fixate an algorithm, which is okay for SASL (for a specific mechanism)

RVR: I'm assuming, because you did not say so, that this is the token format.  You are sending binary content, from the looks of it.

RVR: Raising issues whether "utf8 null-terminated" permits null chars internally (of course not) and whether overlong forms are permitted (probably not) and definately not their combination (multi-byte nulls without an actual byte value 0x00).  What colour of bullet do you fire when you encounter them?

## Server responds to an OPAQUE credential request

RVR: "CreateCredentialResponse()" looks like an API call; turn it into an accurate Normative reference with well-defined input/output parameter connections.

1. the server receives the request from the client.
2. based on the authid and userid the server fetches the user record from its storage backend
3. using the realm or the server FQDN server as the server ID and the userid as the user ID the server calls CreateCredentialResponse(), which returns a credential response, and two sensitive values: the shared key and the user authentication code.
4. the server concatenates the credential response from OPAQUE and the null-terminated utf8 encoded realm and sends this to the client.

~~~
response {
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
}
~~~

RVR: The token is framed in SASL, so the trailing NUL is not *necessary* here

## Client recovers credentials authenticates server

RVR: realms are incredibly confusing in SASL.  Given what I've seen about Realm Crossover I am tempted to consider it the scope for a userid, which is especially clear when you treat them separately.  Say, you login to gmail -- would the "stef" account belong under your realm or theirs?  In the former case, you can support multiple realms on one server.

RVR: "fromt" --> "from"

RVR: "RecoverCredentials()" looks like an API call; turn it into an accurate Normative reference with well-defined input/output parameter connections.

1. The client uses the userid and the realm as the user and the server IDs, the sensitive context fromt the first step and calls RecoverCredentials().
2. RecoverCredentials() returns a shared key and the authentication code.
3. The client sends the authentication code back to the server.

~~~
client_response {
  u8 auth[64];
}
~~~

## Server authenticates client

1. The Server uses the authentication token calculated during the creation of the credential response, and the authentication token received from the client and calls UserAuth() with them as parameters. If this succeeds, the server signals successful authentication, otherwise it signals authentication failed.

RVR: "The server does not send additional data along with a reported success."

RVR: Where is the "UserAuth()" procedure defined, I did not find it in the Normative reference; what are its inputs/outputs?

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
