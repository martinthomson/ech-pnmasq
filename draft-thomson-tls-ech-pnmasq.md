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
are obscured.

The use of multiple public names
can undermine the effectiveness of ECH
if poorly implemented;
{{deployment}} includes a discussion of these considerations.
This approach also cannot hide the use of IP addresses
that correspond to a set of hidden names.


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
including an analysis of drawbacks; see {{authn}}.


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Alternative Retry Authentication {#authn}

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

An ECH configuration with this extension
refers to a public name
that the operator of the client-facing server
might not have a valid certificate for;
see {{name-selection}}.
Clients that use an ECH configuration with this extension
MUST follow the process for authenticating an ECH retry
described in {{retry-authn}}.

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


# Retry Configuration Authentication {#retry-authn}

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


## Public Name Selection {#name-selection}

The public name used in the ECH configuration
does not need to be valid according to any grammar.
Any sequence of octets
up to the limit for public names (255 bytes)
is possible.

Names that appear to be domain names
are most likely to be widely compatible.
That is, names formed from a sequence LDH labels,
as defined in {{Section 2.3.1 of ?IDNA=RFC5890}},
each joined with periods ('.').


## Name Mappings {#unique-mapping}

A simple method for generating public names
is to generate a fresh name
for every ECH configuration.
If every public name is different,
then each public name uniquely maps
to a single hidden name.

A unique public name for each request therefore depends
on the ECH configuration remaining secret.
Unique names are incompatible with distribution using DNS,
which involves shared caches at recursive resolvers.
An adversary that is able to obtain
the ECH configuration from a shared DNS cache
would be able to learn the hidden name
that corresponds to the included public name.

It is therefore important that any given public name
be plausibly associated with multiple hidden names.
This can be achieved by increasing
the size of the anonymity set,
together with the inclusion of information that
diversifies the public name.


# Sample Procedures

A deployment can generate a secret
and distribute that secret
to all client-facing servers
and all authoritative name servers.
A corresponding short key identifier
might be generated using a counter.

The secret can be split into two parts for use:

* A key for enciphering public names ({{sample-pn-enc}}).

* A key for generating authentication keys ({{sample-authn-key}}).

These secrets are used to
generate public names that encode information
about the ECH profile to select (see {{profiles}}).


## Key Lifetime {#key-lifetime}

If public names are encrypted,
the lifetime of any keys that are used needs
to exceed the lifetime of ECH keys.
Otherwise, servers will be unable to recover
when clients use old ECH configurations.

The keys used to protect public names only exist
to protect the extent of the anonymity set.
These keys can be rotated less often
than the keys that are used to protect hidden names.

Because these keys are only used if a retry is necessary,
it might be possible to ensure that they are only valid
during a periodic transition of ECH keys.
This depends on being able to propagate ECH configurations
to all clients
between the time that these keys are emplaced
and when the ECH keys are changed out.


## ECH Profiles {#profiles}

These procedures assume that a client-facing server
maintains multiple active ECH profiles.

ECH profile includes
a config identifier,
an HPKE KEM identifier,
a HPKE key pair,
a set of HPKE symmetric cipher suites,
any other extensions,
and (optionally) a public name for use with clients
that do not support this extension.

A client-facing server can limit the number of such profiles
it supports at the one time.
Each profile can be allocated an identifier.
This identifier needs to be unique
within the set of profiles that might be concurrently active.
An identifier that is unique over a wide scope
is inadvisable as that makes it more difficult
to avoid creating unique name mappings.

At any given time, each hidden name is mapped to a single profile.
However, over time,
hidden names might be mapped to different profiles,
as key pairs are rotated
or changes are made to account for different deployment strategies.

With an unmodified ECH deployment,
a client-facing server uses the combination of
the `config_id` from the outer "encrypted_client_hello" extension
and the public name from the "server_name" extension
to recover a profile.

In this design,
a client-facing server uses the same information,
except that the true profile identifier is encrypted
and encoded into these two fields.


# Sample Public Name Generation Method {#sample-pn-enc}

Public names might be generated by
enciphering the profile identifier.

Additional information is added to the name to ensure
that there is a limited amount of diversity in public names.
The amount of entropy included for diversification is limited
so that there is a non-negligible chance that
different inputs produce the same outcome.
This can be achieved by hashing the inputs used for diversifying names
and taking a limited number of bits from the output.

Inputs used for diversification include:

* The IP address of the DNS client,
  or the DNS Client Subnet option,
  if present.

* The current time,
  rounded to the expected DNS record TTL
  or a small integer fraction of that time.
  For instance, with a TTL of 30 seconds
  the time might be rounded to multiples of 5 seconds.

* A small amount of randomness that will
  ensure that the resulting public name is less predictable.

In the following pseudocode
'`^`' is an exclusive OR,
'`||`' is concatenation,
and '`[a..b]`' takes a range of bits
from bit '`a`' (inclusive, default 0) to bit '`b`' (exclusive).
This code also uses functions for randomness ('`random()`'),
a collision-resistant hash ('`H()`'),
a pseudorandom function ('`prf()`'),
and encoding a byte sequence as a DNS name ('`encode_dns()`').

~~~ pseudocode
k1 = prf(secret, "k1" || key_id)
r = random()[..RANDOM_BITS]
diversity = H(client_ip || time || r)[..DIVERSITY_BITS]
k2 = prf(secret, "k2" || diversity)

d = key_id || k1 ^ (diversity || k2 ^ profile_id)

config_id = d[0..8]
public_name = encode_dns(d[8..])
~~~

{:aside}
> Note that the PRF function only needs
> to produce enough bits
> to mask the value it obscures using XOR.
> Any additional bits can be discarded.

{:aside}
> ISSUE:
> This approach reveals to an observer that two
> values share a `diversity` value.
>
> Something like format-preserving encryption
> might be necessary.
> For instance,
> a Feistel network might ensure that the entire value
> depends on all inputs,
> including the profile identifier.
>
> The challenge being that
> the two layers of protection here,
> to protect the profile identifier
> and the diversity value,
> would each require an application of the network.


### Authenticated Encryption

The use of authenticated encryption {{?AEAD=RFC5116}}
is not necessary to achieve privacy goals.
Authentication identifies any name
that is generated without access to the key.

Avoiding authentication ensures that an adversary
is unable to use side channels
to determine whether any given public name is valid
as all public names receive the same treatment.

Authenticated encryption could be used
if a deployment is concerned about
the cost of responding to connection attempts.
This approach could lead to
a significant amount of additional load
on servers due to the need to generate authentication keys
and certificates for every unique public name.

Using authenticated encryption only
increases the length of public names;
it does not increase the diversity of names.
Authentication of names therefore
does not affect the potential privacy of public names.


### Parameter Selection

An adversary that is able to make a request
at about the same time
and from the same client IP or subnet
will learn the mapping from hidden name to public name.
Including more randomness
will reduce the odds that the same public name
is used for a different hidden name.

The optimal number of random bits that are added
(`RANDOM_BITS`)
depends on the number of hidden names that
correspond to the same profile identifier,
that is, the size of the anonymity set.
Larger anonymity sets allow for more diversity in names
as there are more public names generated
and a higher chance of collision.

For `RANDOM_BITS`,
generating less than twice the number of bits
as the base-2 logarithm of the anonymity set size
ensures that a collision across the names in the set
is highly likely.

Combining this information using a hash function,
then taking a limited number of bits
ensures that the number of public names is limited.
This improves the chances that the same public name
is generated for different hidden names.
The number of bits that are retained
(`DIVERSITY_BITS`)
can exceed the number of random bits,
but only based on the expected number of different
ECH configurations that might be concurrently active
for the anonymity set.

Setting `DIVERSITY_BITS` to less than twice
the base-2 logarithm of the total number of ECH configurations
ensures that a collision across the names in the set
is highly likely.
The total number of ECH configurations can be determined
empirically as the number of queries that are answered
with different answers
for hidden names with the same profile
within a TTL.
Alternatively, the number of possible active ECH configurations
is the anonymity set size
times an estimate of the number of different resolvers.
The alternative approach likely produces a larger value,
so it might be adjusted downward by a constant factor.

In both cases,
a minimum amount random entropy
ensures that even small anonymity set has some diversity.
A minimum of 5 bits ensures that
every hidden name produces public names
from 32 different options.


### Retry Configuration Generation

The process described here can be greatly simplified
for ECH configurations that are
generated by a TLS server
and sent in the "retry_configs" field.

Every ECH configuration that is provided
using "retry_configs"
can be unique.
This can be achieved
by setting `DIVERSITY_BITS` and `RANDOM_BITS`
to values that are large enough to ensure
that the collision risk is negligible.
The only relevant consideration is
the length of the resulting public name.

If a different scheme is used
for generating public names
based on how the ECH configurations are delivered,
it is necessary to distinguish between the forms.
This could use the unprotected key identifier
or just the length of the name
(using a larger value of `DIVERSITY_BITS`
likely results in a longer name).


## Sample Authentication Key Generation Method {#sample-authn-key}

An ECH configuration can be generated by
an authoritative resolver
in response to request.

A SVCB (or equivalent, like HTTPS) RR for a hidden name
is first mapped to an identifier for the anonymity set.
This might be the public name
that is provided to clients
that do not support this extension.

The resolver then collects information
that might be used to diversify the name.
This includes the client IP address or subnet prefix,
the time,
and potentially a small amount of randomness;
see {{unique-mapping}}.

An authentication key might be generated as a function of the public name,
and optionally the config_id,
using a pseudorandom function (PRF) that is keyed with the secret.


# Security Considerations {#security}

Use of this mechanism inherits
many of the security considerations from {{Section 10 of ECH}}.
Depending on how it is deployed,
it can alter the privacy characteristics,
as it obscures the extent of an anonymity set
presented by a client-facing server;
see {{Section 10.1 of ECH}}.


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


## Configuration Availability

An adversary that is able to obtain
every ECH configuration that is ever produced
can recover the anonymity set perfectly.
This design therefore depends on
adversaries being unable to
access all ECH configurations.

Clients that use shared DNS caching resolvers
are less able to benefit from these protections.
Caching resolvers can improve privacy protections
by including the Client Subnet option {{?RFC7871}}
in DNS queries.
Authoritative resolvers are then able to
change the public name based on the Client Subnet prefix.
An adversary would then need to
present an IP address with the same prefix as a target
to learn the ECH configuration
that the target was presented with.

A shorter TTL on resource records
increases the work required by an adversary.


## Unique Mapping To Hidden Names

The use of a unique public name
could identify the hidden name.
If each hidden name corresponds to a different public name,
an adversary that is able to obtain that mapping
might reverse the mapping to recover the hidden name
from the unprotected "server_name" extension.
This attack is addressed in {{unique-mapping}}.


## Client Privacy

The method in {{unique-mapping}} recommends
the inclusion of a client IP address
or the identity of its DNS recursive resolver
in the derivation of a public name.
This introduces a potential privacy leak.

Any entity that can observe the TLS handshake
and is also able to obtain the same ECH configuration
might be able to learn something about the client IP address
or DNS resolver from the public name that is used.
The client-facing server also obtains the same information
with higher certainty.

This risk is partly counteracted by
the use of an entropy narrowing function
as part of the public name generation process.
That increases the chances that different inputs
result in the same public name.
However, if an adversary only seeks to improve their confidence
in an existing hypothesis of client identity,
this is unlikely to be sufficient.

A client that uses a tunnel,
such as a VPN or proxy,
for privacy purposes
can avoid leaking unwanted information
by accessing a DNS resolver using the tunnel.
This is also good practice
for the use of this sort of privacy mechanism
for reasons other than privacy,
such as ensuring that services are selected
for proximity to the tunnel egress point
rather than proximity to the client.


# IANA Considerations {#iana}

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
