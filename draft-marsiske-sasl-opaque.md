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
  3DH:
    title: The Double Ratchet Algorithm
    target: https://signal.org/docs/specifications/doubleratchet/
  XCHACHA20:
    title: XChaCha: eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305
    target: https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/03/

--- abstract

This document describes the OPAQUE{{OPAQUE}} protocol SASL mechanism. OPAQUE is a secure asymmetric password-authenticated key exchange (aPAKE) that supports mutual authentication in a client-server setting without reliance on PKI and with security against pre-computation attacks upon server compromise. This document specifies the messages between a SASL server and client using the OPAQUE protocol for authentication.

--- middle

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Introduction

OPAQUE is an efficient, versatile, modern cryptographic primitive with strong security guarantees that goes beyond what existing SASL mechanisms provide. One of the most important features is that the user's password or anything derived from it is neither exposed to the server nor in the protocol.  Another important security property is that replay attacks are not possible.  OPAQUE can be used can be used over plaintext channels, although the lack of binding between authentication and the rest of the protocol usually form an independent reason to not use that.

The closest SASL authentication mechanism to OPAQUE is SRP {{?RFC2945}}, which is vulnerable to pre-computation attacks, lacks proof of security, and is less efficient than OPAQUE. Moreover, SRP requires a ring as it mixes addition and multiplication operations, and thus does not work over standard elliptic curves. OPAQUE is therefore a suitable replacement for applications that use SRP.

# Notation {#notation}

All protocol messages and structures defined in this document use the syntax from {{?RFC8446, Section 3}}.

# Protocol overview

This specification instantiates OPAQUE-3DH with the following configuration tuple ({{OPAQUE}} configurations section): (OPRF(ristretto255, SHA-512), HKDF-SHA-512, HMAC-SHA-512, SHA-512, argon2i(67108864, 2), ristretto255). The sizes of all message components are set accordingly.

The messages closely follow the specification of OPAQUE AKE messsages({{OPAQUE}} AKE messages section), and any field names and calls not defined herein are clarified in that specification.

SASL OPAQUE is a client-initiated mechanism. In total 3 messages are necessary to authenticate the client to the server.

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
2. based on the authid and userid the server fetches the user record from its storage back-end
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

OPAQUE guarantees that the users passwords are never exposed to the
server (see registration caveat below). This protects against the
users passwords being logged as plaintext, or other exposure when TLS
may fail, including PKI attacks, certificate mishandling, termination
outside the security perimeter, visibility to TLS-terminating
intermediaries.

OPAQUE also provides an optional enumeration mitigation by responding
with a fake "response" to requests for non-existing clients. This is
something that the server implementation should support. For more
details on this see the "preventing-client-enumeration" section of the
OPAQUE{{OPAQUE}} RFC.

The security considerations of the OPAQUE{{OPAQUE}} RFC also apply to
the SASL mechanism. Additional security considerations are:

1. This SASL mechanism specification does not define channel binding,
   however it is possible to achieve this by adding the channel
   binding information to the user and server name. The details of
   this depend strongly on the channel being bound. The OPAQUE RFC
   notes this:
   > In principle, identities may change across different sessions as
   > long as there is a policy that can establish if the identity is
   > acceptable or not to the peer.
2. This specification does not define a secure layer protocol, despite
   OPAQUE lends itself perfectly to establish the keying of such. It
   is debatable what kind of SL could be initialized from OPAQUE, it
   could be a simple XChacha20/Poly1305{{XCHACHA20}} channel, some form of
   Double-Ratchet{{3DH}}, or even using TLS {{?TLSv1.3=RFC8446}}
   PSK_KE mode all these variants have their pros and cons.
3. The OPAQUE RFC only specifies the 4 step
   password-privacy-protecting registration procedure, which does not
   apply to how SASL creates new users. With SASL new users are
   usually added on the server by using a tool like saslpasswd2 which
   creates the accounts for all SASL supported mechanisms, and thus
   the users password is exposed to the server. On one hand this
   violates one of OPAQUEs strengths, never exposing the password to
   the server, but on the other hand it enables the server to enforce
   password quality rules. It is warmly recommended for implementers
   to provide means to create new users by applying the 4 step
   procedure also specified by the OPAQUE RFC.
4. Key-Stretching Functions (such as Argon2 {{?ARGON2=RFC9106}},
   scrypt {{?SCRYPT=RFC7914}}, and PBKDF2 {{?PBKDF2=RFC2898}}) are
   only executed and used on the client. This has a couple consequences:
   - it eliminates a resource-exhaustion DoS attack vector against the
     server.
   - implementers must consider low-resource clients which might be
     overwhelmed by overly resource-intensive KSF configurations.
   - clients can choose their KSF independently of the server, the
     only important detail is that all clients must use the same KSF
     config for the same user record. Client KSF configuration might
     be stored at client side in a configuration, although this
     eliminates one of the benefits of OPAQUE of not needing any info
     besides the user password on the client, but this might be
     unimportant for a lot of applications.

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
