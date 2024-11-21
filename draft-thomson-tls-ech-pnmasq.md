---
title: "Public Name Masquerade for TLS Encrypted Client Hello"
abbrev: "Public Name Masquerade"
category: std

docname: draft-thomson-tls-ech-pnmasq-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Transport Layer Security"
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
  group: "Transport Layer Security"
  type: "Working Group"
  mail: "tls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/tls/"
  github: "martinthomson/retch-sik"
  latest: "https://martinthomson.github.io/retch-sik/draft-thomson-tls-retch-sik.html"

author:
 -
    fullname: "Martin Thomson"
    organization: Mozilla
    email: "mt@lowentropy.net"
 -
    fullname: "Marwan Fayed"
    organization: Cloudflare
    email: marwan@cloudflare.com

normative:

informative:


--- abstract

TODO Abstract


--- middle

# Introduction

In a TLS Encrypted Client Hello (ECH) {{?ECH=I-D.ietf-tls-esni}},
the level of privacy is directly proportional to the number of
possible name(s) that could be encrypted in the
`ClientHelloInner` relative to the name(s) in the
`ClientHelloOuter`.
[comment]: However, as the anonymity set that results
[comment]: depends on IP address, public name, and other configuration
[comment]: parameters, perfect uniformity is essentially impossible to
[comment]: achieve.
This means that privacy is defined by the 'herd' of names and not
of users, in direct contrast to longer-standing schemes for
secure or private communication such as VPNs, Tor, and oblivious
proxies, to name a few. For example, say a server can
authenticate domains `example-1.com` through `example-5.com`,
inclusive, and the server populates its `echconfig` with
`example-ech.com`. In this case, an observer's ability to know
the contents of the ClientHelloInner is neither advantaged nor
disadvantaged by the number of users connecting to the
ClientHelloOuter.

The natural way to improve privacy in this setting is to maximize
the uniformity of visible information that is revealed to
adversaries. An ideal arrangement uses a single consistent ECH
configuration
{{https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-22#name-encrypted-clienthello-confi}}
across
[comment]: all clients or, alternatively, across
all providers and servers. A single configuration creates an
anonymity set consisting of all names from all servers.

However, a consistent configuration negates any single server's
ability to authenticate itself on the SNI in the
ClientHelloOuter. Authentication against a public name is needed
so the server can safely invoke a retry mechanism, for example,
when a client attempts to use outdated or incorrect
configuration. This recovery is an essential feature of ECH that
also ensures a server attempts to decrypt only those ECH
connections it expects, for example, so that a server for
example.com does not attempt to decrypt ECH connections for
not-example.com.

However, the need to authenticate a public name also limits the size of
the anonymity set to the number of names available at the server,
thereby upper-bounding ECH privacy to its server's deployment.

**MF PICK UP FROM HERE**

A reduction occurs when a service needs to use
the different public name values.
The public name is chosen for the server deployment
that clients put in the unprotected "server_name" extension.
A server deployment might rely on the public name
to route incoming connections
or select from different ECH configurations.

Each server operator might seek
to ensure that it uses the minimum possible
number of configurations to maximize the effective privacy.
However, this can be at odds with operational constraints
that might push toward having more diverse configurations.

## Unique Public Names

This document describes an approach that seeks
to improve privacy by increasing the number of public names.
Rather than having as few public names as possible,
it increases the size of the anonymity set
for public names
by using as many public names as possible.

In the ideal form of this approach,
a unique public name is used for each client.
In practice,
caching of HTTPS records {{?RFC9460}}
will ensure that the same public name
is likely to be used by some number of clients.

Any reuse of a name will cluster clients
into relatively small anonymity sets.
Any clustering will be based on attributes
that already leak to a passive observer.
This includes the time, the network that a client uses,
or the choice of DNS resolver.

The net effect is that the public name
is either unique (used for a single connection)
or forms a small anonymity set (used for a small number of connections).
Assembling observed connection attempts
into group that represents the true anonymity set
requires that an adversary obtain mappings for all of the public names
that correspond to the same hidden names.

The net effect is similar to publishing
multiple different encryptions of public names.
This increased diversity of public names
leads to a much larger effective anonymity set,
except to the extent that adversaries are able to
recover the mapping of each public name to hidden names.
Both the public name and other ECH configuration values,
such as HPKE {{?RFC9180}} parameters,
are effectively obscured.
However, this approach cannot hide the use of IP addresses
that correspond to a set of hidden names.


## Recovery of Anonymity Sets

This design only permits linking public names
based on what an adversary can observe about the relation
between each hidden name
and all of the public names that are used for that each hidden name.

Obviously, the reuse of a name
would reveal that two identical names share a configuration.
The use of ECH still means that uses of those public names
could correspond to different hidden names.

To provide a comprehensible view of the true anonymity set,
an adversary would need to obtain all public names
that are in use across all hidden names.
If different names are provided in response to every DNS query
from an authoritative resolver,
an adversary would --
at best --
need to query every DNS resolver cache that queries that authoritative.
This makes it far more difficult
to get a precise enumeration of the names that correspond
to any given anonymity set.


## Alternative Authentication for Public Names

This document defines a new method
for validating the certificate that a server proffers
during an ECH retry.
This enables a retry process that does not
depend on the public key infrastructure
that is used for server authentication,
making it far easier to create new public names.

These names can even overlap with
parts of the domain name system.
The client determines
whether a server is authorized to provide
an ECH retry configuration
based on the choice of name alone.
This removes any need to rely on anything other than
the public key that is bound to the name.
This obviates any need for revocation checks,

This change to public name authentication
is the only aspect of this document that requires
client changes.
This document describes a server architecture
that helps demonstrate the feasibility of this approach,
including an analysis of drawbacks.


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Alternative Retry Authentication

ECH defines a retry process
for when the ECH configuration that a client uses
is rejected by a server.
The server completes the handshake
using the outer (or unprotected) ClientHello.

By default, the server offers a certificate
that is valid for the outer "server_name" that is used.
The client then authenticates the handshake
using that certificate
and the process by which a client would ordinarily
validate a server identity.

That ordinary process relies on
the client having previously established
which name it wishes to authenticate.
The name that is used during an ECH retry
comes from the ECH configuration.
The ECH configuration is typically obtained
from the SVCB record {{?SVCB=RFC9460}},
which ECH treats as unauthenticated;
see {{Section 10.2 of ECH}}.

The client therefore relies on the ECH configuration
to choose the public name that it authenticates.
This opens the possibility that the ECH configuration
can also specify alternative means of authentication.

The public name therefore does not need to be valid
according to ordinary client expectations.
The public name exists solely to carry information to the server
about the anonymity set
into which the connection attempt falls.
The public name value could even be encrypted;
see {{deployment}}.

This document defines an ECH configuration extension,
"public_name_authn",
that specifies an alternative name
and the means by which that alternative name is authenticated.


# ECH Public Name Masquerade Extension {#extension}

An extension is defined for ECH
that includes a randomized name
and information necessary to authenticate
the TLS handshake that
supplies an ECH retry configuration.

~~~ tls-syntax
struct {
  SignatureScheme scheme;
  opaque spki_hash[32];
} PublicNameAuthentication;
~~~
{: #fig-pn-auth title="public_name_authn Extension Structure"}

This extension is defined as mandatory,
because a server that uses this approach
relies on clients applying
the alternative authentication method
to validate the public name.

Clients MUST NOT use an ECH configuration
with this extension
unless the connection they establish
includes the indicated signature scheme
in a "signature_algorithms" extension.

{:aside}
> This might be marginally more compatible
> if the extension were optional.
> In that case, the extension would have to
> include the bogus public name as well,
> which would be less efficient in the longer term.
>
> In the short term, this approach is less efficient
> as it forces a server that wishes
> to support clients that do not support this extension
> to provide additional configurations.


# Retry Configuration Authentication

A server that rejects an ECH configuration
can use a certificate or raw public key {{?RAW=RFC7250}}.
Clients extract the `subjectPublicKeyInfo`,
either from the certificate or,
for raw public keys,
the Certificate message content.

The resulting `subjectPublicKeyInfo` structure
is hashed using SHA-256
and compared to the `spki_hash` value from the
"public_name_authn" extension in the ECH configuration.
If the value matches,
the retry configuration is accepted.
Otherwise, the connection attempt MUST be aborted
and any retry configuration that is provided
is discarded.

This procedure largely replaces the procedure
in {{Section 6.1.7 of ECH}}.
This does not change the requirement that
the client not
provide a certificate if requested
or regard the connection as authenticated for the origin.


# Deployment Considerations {#deployment}


## Key Lifetime {#key_lifetime}

If public names are encrypted,
the lifetime of any keys that are used needs
to exceed the lifetime of ECH keys.
Otherwise, servers will be unable to recover
when clients use old ECH configurations.

The keys used to protect public names only exist
to protect the extent of the anonymity set.
These keys can be rotated less often
than the keys that are used to protect hidden names.


## Unique Name Mappings {#unique_mapping}




# Security Considerations

The use of a unique public name
could identify the hidden name.
If each hidden name corresponds to a different public name,
an adversary that is able to obtain that mapping
might reverse the mapping to recover the hidden name
from the unprotected "server_name" extension.
This attack is addressed in {{unique_mapping}}.



# IANA Considerations

This document registers an extension
in the TLS "ECH Configuration Extension Registry"
established by {{!ECH}}.

Value:
: 0xTBD (value has to be 0x8000 or greater)

Extension Name:
: public_name_authn

Recommended:
: Y

Reference:
: This document

Notes:
: (none)
{: spacing="compact"}


--- back

# Acknowledgments
{:numbered="false"}

TODO
