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

normative:

informative:


--- abstract

TODO Abstract


--- middle

# Introduction

The TLS Encrypted Client Hello {{?ECH=I-D.ietf-tls-esni}}
defines a fallback mechanism
that is used when a client attempts to use
outdated or incorrect configuration.

This recovery is an essential feature of ECH,
but it contributes to a reduction in the size of
the anonymity set for connection attempts.
This reduction occurs when a service needs to use
the different unprotected server name values.
A server deployment might rely on the unprotected server name
to route incoming connections
or select from different configurations.

The natural way to improve privacy in this setting is
to maximize the uniformity of information
that is revealed to adversaries.
For privacy purposes,
the ideal arrangement being
a single consistent configuration
across all clients.
However, as the anonymity set that results
depends on IP address, public name, and
other configuration parameters,
perfect uniformity is essentially impossible to achieve.

Each server operator might seek
to ensure that it uses the minimum possible
number of configurations to maximize the effective gprivacy.
However, this can be at odds with operational constraints
that might push toward having more diverse configurations.

## Unique Public Names

This document describes an approach that seeks
to improve privacy by taking the opposite approach.
Rather than having as few public names as possible,
it increases the size of the anonymity set
for public names
by using as many public names as possible.

In the extreme,
this might involve having a unique public name for each client.
In practice,
caching of HTTPS records {{?RFC9460}}
will ensure that the same public name
is likely to be used by some number of clients.

Any reuse of a name will cluster clients into relatively small
anonymity sets,
but any clustering will be based on attributes
that already leak to a passive observer.
This includes the time, the network that a client uses,
or the choice of DNS resolver.

The net effect is that the public name
is either unique (used for a single connection)
or forms a small anonymity set (used for a small number of connections).
Such names would include no obvious means of correlation
that can be used by a passive observer
to form a useful anonymity set.

The net effect is similar to publishing
multiple encryptions of chosen public names.
This increased diversity of public names
leads to a much larger effective anonymity set,
except to the extent.
This includes both the public name and HPKE {{?RFC9180}} parameters.
However, it cannot hide the use of IP addresses
if those are correlated with a set of server names.


## Recovery of Anonymity Sets

This design only permits linking public names
based on actual observed relations
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


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
