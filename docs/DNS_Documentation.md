---
title: Domain Name System (DNS)
header-includes:
    <meta name="author" content="William Fleetwood" />
---

>**TODO**
>
>* Update to include DNSSEC values
>* Include EDNS section of packet
>* Include sections of general resolution protocol, query/response, recursive/authoritative servers
>* Include updated Negative Caching
<br>

# Introduction

This document describes the Domain Name System (DNS), including the design, server roles, algorithms, data, use cases, and on the wire message protocol that make up the DNS.
The DNS design and usage is defined in a large number of different RFCs starting back in 1983, many of which have been corrected, clarified, extended, updated, or made completely obsolete by more modern RFCs. This makes understanding the current DNS specifications in its entirety quite difficult and realistically impossible for most people.

In order to combat this issue, and thus make any future DNS development both easier and more accurate, this document attempts to compile all the relevent DNS RFCs into one single, up to date, clear, all encompassing document. Note that in the future, depending on the size of this document, it may be split up into multiple documents for readability.

For a complete list of DNS related RFCs, see [https://www.bind9.net/rfc](https://www.bind9.net/rfc).

Compiled RFCs:

* [RFC-1033](https://www.ietf.org/rfc/rfc1033.txt)
* (*WIP*) [RFC-1034](https://www.ietf.org/rfc/rfc1034.txt)
* (*WIP*) [RFC-1035](https://www.ietf.org/rfc/rfc1035.txt)
* [RFC-2308](https://www.ietf.org/rfc/rfc2308.txt)
* [RFC-3425](https://www.ietf.org/rfc/rfc3425.txt)
* (*TODO*) [RFC-4033](https://www.ietf.org/rfc/rfc4033.txt)

The following RFCs are only relevent to DNS management operations, or are better described in other RFCs, and thus do not affect DNS behavior itself:

* [RFC-881](https://www.ietf.org/rfc/rfc881.txt)
* [RFC-897](https://www.ietf.org/rfc/rfc897.txt)
* [RFC-921](https://www.ietf.org/rfc/rfc921.txt)
* [RFC-1032](https://www.ietf.org/rfc/rfc1032.txt)

This document and its source, as well as a DNS library written in Rust which uses this documentation as a source of truth, is hosted on [https://github.com/willfleetw/rusty_dns](https://github.com/willfleetw/rusty_dns).

<br>

# DNS Introduction

The DNS should be thought of as a distributed, hierarchical, somewhat limited database potentially capable of storing almost any type of data. Every piece of data in the DNS is mapped to a domain name, a class, and a type.

The DNS has three major components:

   - The DOMAIN NAME SPACE and RESOURCE RECORDS, which are
     specifications for a tree structured name space and data
     associated with the names. Conceptually, each node and leaf
     of the domain name space tree names a set of information, and
     query operations are attempts to extract specific types of
     information from a particular set. A query names the domain
     name of interest and describes the type of resource
     information that is desired. For example, the Internet
     uses some of its domain names to identify hosts; queries for
     address resources return Internet host addresses.

   - NAME SERVERS are server programs which hold information about
     the domain tree's structure and set information. A name
     server may cache structure or set information about any part
     of the domain tree, but in general a particular name server
     has complete information about a subset of the domain space,
     and pointers to other name servers that can be used to lead to
     information from any part of the domain tree. Name servers
     know the parts of the domain tree for which they have complete
     information; a name server is said to be an AUTHORITY for
     these parts of the name space. Authoritative information is
     organized into units called ZONEs, and these zones can be
     automatically distributed to the name servers which provide
     redundant service for the data in a zone.

   - RESOLVERS are programs that extract information from name
     servers in response to client requests. Resolvers must be
     able to access at least one name server and use that name
     server's information to answer a query directly, or pursue the
     query using referrals to other name servers. A resolver will
     typically be a system routine that is directly accessible to
     user programs; hence no protocol is necessary between the
     resolver and the user program.

<br>

## Domain Name Space

```
                             . (ROOT)
                             |
                             |
         +---------------------+------------------+
         |                     |                  |
     MIL                   EDU                ARPA
         |                     |                  |
         |                     |                  |
 +-----+-----+               |     +------+-----+-----+
 |     |     |               |     |      |           |
 BRL  NOSC  DARPA             |  IN-ADDR  SRI-NIC     ACC
                             |
 +--------+------------------+---------------+--------+
 |        |                  |               |        |
 UCI      MIT                 |              UDEL     YALE
         |                 ISI
         |                  |
     +---+---+              |
     |       |              |
     LCS  ACHILLES  +--+-----+-----+--------+
     |             |  |     |     |        |
     XX            A  C   VAXA  VENERA Mockapetris
```

The domain name space is a tree structure. Each node and leaf on the
tree corresponds to a resource set (which may be empty). The domain
system makes no distinctions between the uses of the interior nodes and
leaves, and the term "node" refers to both.

Each node has a label, which is zero to 63 octets in length. Sibling
nodes may not have the same label, although the same label can be used
for nodes which are not siblings. One label is reserved, and that is
the null (i.e., zero length) label used for the root.

The domain name of a node is the list of the labels on the path from the
node to the root of the tree. By convention, the labels that compose a
domain name are printed or read left to right, from the most specific
(lowest, farthest from the root) to the least specific (highest, closest
to the root), which each label being seperated by a ".". The domain name of
a node ends with the root label, and is often written as ".". For example,
the domain name of the "XX" node on the tree would be written as
"XX.LCS.MIT.EDU.".

By convention, domain names can be stored with arbitrary case, but
domain name comparisons for all present domain functions are done in a
case-insensitive manner. When receiving a domain name or label, you should
preserve its case.

When a user needs to type a domain name, the length of each label is
omitted and the labels are separated by dots ("."). Since a complete
domain name ends with the root label, this leads to a printed form which
ends in a dot. We use this property to distinguish between:

   - a character string which represents a complete domain name
     (often called "absolute"). For example, "poneria.ISI.EDU."

   - a character string that represents the starting labels of a
     domain name which is incomplete, and should be completed by
     local software using knowledge of the local domain (often
     called "relative"). For example, "poneria" used in the
     ISI.EDU domain.

Internally, programs that manipulate domain names should represent them
as sequences of labels, where each label is a length octet followed by
an octet string. Because all domain names end at the root, which has a
null string for a label, these internal representations can use a length
byte of zero to terminate a domain name.

To simplify implementations, the total number of octets that represent a
domain name (i.e., the sum of all label octets and label lengths) is
limited to 255.

<br>

## Domain Name CFG

```
<domain>        ::= <subdomain> | " "

<subdomain>     ::= <label> | <subdomain> "." <label>

<label>         ::= <letter> [ [ <ldh-str> ] <let-dig> ]

<ldh-str>       ::= <let-dig-hyp> | <let-dig-hyp> <ldh-str>

<let-dig-hyp>   ::= <let-dig> | "-"

<let-dig>       ::= <letter> | <digit>

<letter>        ::= a single upper or lower case alphabetic character

<digit>         ::= any one of the ten digits 0 through 9
```

Note that while upper and lower case letters are allowed in domain
names, no significance is attached to the case. That is, two names with
the same spelling but different case are to be treated as if identical.

The labels must follow the rules for ARPANET host names. They must
start with a letter, end with a letter or digit, and have as interior
characters only letters, digits, and hyphen. There are also some
restrictions on the length. Labels must be 63 characters or less.
(This means first two bits of all labels are always 0).

<br>

## Resource Records (RRs)

A domain name identifies a node. Each node has a set of resource
information, which may be empty. The set of resource information
associated with a particular name is composed of separate resource
records (RRs). The order of RRs in a set is not significant, and need
not be preserved by name servers, resolvers, or other parts of the DNS.

When we talk about a specific RR, we assume it has the following:

| Field | Description |
| ----- | ----------- |
| OWNER | The domain name where the RR is found |
| TYPE  | An encoded 16 bit value that specifies the type of the resource in this resource record. Types refer to abstract resources |
| CLASS | An encoded 16 bit value which identifies a protocol family or instance of a protocol |
| TTL   | The time to live of the RR. This field is a 32 bit integer in units of seconds, an is primarily used by resolvers when they cache RRs. The TTL describes how long a RR can be cached before it should be discarded |
| RDATA | The type and sometimes class dependent data which describes the resource |

<br>

## Textual Expression of RRs

RRs are represented in binary form in the packets of the DNS protocol,
and are usually represented in highly encoded form when stored in a name
server or resolver.

The start of the line gives the owner of the RR. If a line begins with
a blank, then the owner is assumed to be the same as that of the
previous RR. Blank lines are often included for readability.

Following the owner, we list the TTL, type, and class of the RR. Class
and type use the mnemonics defined above, and TTL is an integer before
the type field. In order to avoid ambiguity in parsing, type and class
mnemonics are disjoint, TTLs are integers, and the type mnemonic is
always last. The IN class and TTL values are often omitted from examples
in the interests of clarity.

The resource data or RDATA section of the RR are given using knowledge
of the typical representation for the data.

For example, we might show the RRs carried in a message as:

    ISI.EDU.        MX      10 VENERA.ISI.EDU.
                    MX      10 VAXA.ISI.EDU.
    VENERA.ISI.EDU. A       128.9.0.32
                    A       10.1.0.52
    VAXA.ISI.EDU.   A       10.2.0.27
                    A       128.9.0.33

The MX RRs have an RDATA section which consists of a 16 bit number
followed by a domain name. The address RRs use a standard IP address
format to contain a 32 bit internet address.

This example shows six RRs, with two RRs at each of three domain names.

Similarly we might see:

    XX.LCS.MIT.EDU. IN      A       10.0.0.44
                    CH      A       MIT.EDU. 2420

This example shows two addresses for XX.LCS.MIT.EDU, each of a different
class.

<br>

## Aliases and Canonical Names

Many resources might have multiple names that all represent the same thing.
In order to not have the same data duplicated in multiple places, DNS has
the Canonical Name (CNAME) RR.

The CNAME RR identifies its owner name as an alias for another domain name,
known as the canonical name. If a CNAME is present at a node, no other data
should be present.

When a name server of resolver is processing a query, if it happens to encounter
a CNAME it should reset the query resolution to the domain name pointed to by the
CNAME RR. The one exception is when queries match the CNAME type, they are not restarted.

For example, suppose a name server was processing a query with for USC-
ISIC.ARPA, asking for type A information, and had the following resource
records:

    USC-ISIC.ARPA   IN      CNAME   C.ISI.EDU

    C.ISI.EDU       IN      A       10.0.0.52

Both of these RRs would be returned in the response to the type A query,
while a type CNAME or * query should return just the CNAME.

<br>

## Queries

Queries are messages which may be sent to a name server to provoke a
response. In the Internet, queries are carried in UDP datagrams or over
TCP connections. The response by the name server either answers the
question posed in the query, refers the requester to another set of name
servers, or signals some error condition.

In general, the user does not generate queries directly, but instead
makes a request to a resolver which in turn sends one or more queries to
name servers and deals with the error conditions and referrals that may
result. Of course, the possible questions which can be asked in a query
does shape the kind of service a resolver can provide.

DNS queries and responses are carried in a standard message format. The
message format has a header containing a number of fixed fields which
are always present, and four sections which carry query parameters and
RRs.

The most important field in the header is a four bit field called an
opcode which separates different queries. Of the possible 16 values,
one (standard query) is part of the official protocol, one (status query)
is optional, two (inverse and completion query) are obsolete, and the rest
are unassigned.

The four sections are:

| Field | Description |
| ----- | ----------- |
| Question | Carries the query name and other query parameters |
| Answer | Carries RRs which directly answer the query |
| Authority | Carries RRs which describe other authoritative servers. May optionally carry the SOA RR for the authoritative data in the answer section |
| Additional | Carries RRs which may be helpful in using the RRs in the other sections |

Note that the content, but not the format, of these sections varies with
header opcode.

The specific format of the DNS message format is described later in this documentation.

<br>

### Standard Queries

A standard query specifies a target domain name (QNAME), query type
(QTYPE), and query class (QCLASS) and asks for RRs which match. This
type of query makes up such a vast majority of DNS queries that we use
the term "query" to mean standard query unless otherwise specified. The
QTYPE and QCLASS fields are each 16 bits long, and are a superset of
defined types and classes.

Using the query domain name, QTYPE, and QCLASS, the name server looks
for matching RRs. In addition to relevant records, the name server may
return RRs that point toward a name server that has the desired
information or RRs that are expected to be useful in interpreting the
relevant RRs. For example, a name server that doesn't have the
requested information may know a name server that does; a name server
that returns a domain name in a relevant RR may also return the RR that
binds that domain name to an address.

For example, a mailer tying to send mail to Mockapetris@ISI.EDU might
ask the resolver for mail information about ISI.EDU, resulting in a
query for QNAME=ISI.EDU, QTYPE=MX, QCLASS=IN. The response's answer
section would be:

    ISI.EDU.        MX      10 VENERA.ISI.EDU.
                    MX      10 VAXA.ISI.EDU.

while the additional section might be:

    VAXA.ISI.EDU.   A       10.2.0.27
                    A       128.9.0.33
    VENERA.ISI.EDU. A       10.1.0.52
                    A       128.9.0.32

Because the server assumes that if the requester wants mail exchange
information, it will probably want the addresses of the mail exchanges
soon afterward.

Note that the QCLASS=* construct requires special interpretation
regarding authority. Since a particular name server may not know all of
the classes available in the domain system, it can never know if it is
authoritative for all classes. Hence responses to QCLASS=* queries can
never be authoritative.

<br>

### Inverse Queries (Obsolete)

The IQUERY operation was, historically, largely unimplemented in most
name server/resolver software. In addition to this widespread disuse,
the problems stated below made the entire concept widely considered
unwise and poorly thoughtout. Also, the widely used alternate approach
of using pointer (PTR) queries and reverse-mapped records is preferable.
Consequently [RFC-3425](https://www.ietf.org/rfc/rfc3425.txt) declared
it entirely obsolete. As such, any name server or resolver receiving an
IQUERY should return a "Not Implemented" error.

As specified in [RFC-1035](https://www.ietf.org/rfc/rfc1035.txt) (section 6.4), the IQUERY operation for DNS
queries is used to look up the name(s) which are associated with the
given value. The value being sought is provided in the query's
answer section and the response fills in the question section with
one or more 3-tuples of type, name and class.

As noted in [RFC-1035](https://www.ietf.org/rfc/rfc1035.txt), (section 6.4.3), inverse query processing can
put quite an arduous burden on a server. A server would need to
perform either an exhaustive search of its database or maintain a
separate database that is keyed by the values of the primary
database. Both of these approaches could strain system resource use,
particularly for servers that are authoritative for millions of
names.

Response packets from these megaservers could be exceptionally large,
and easily run into megabyte sizes. For example, using IQUERY to
find every domain that is delegated to one of the name servers of a
large ISP could return tens of thousands of 3-tuples in the question
section. This could easily be used to launch denial of service
attacks.

<br>

# Name Servers

Name servers are the repositories of information that make up the domain
database. The database is divided up into sections called zones, which
are distributed among the name servers. While name servers can have
several optional functions and sources of data, the essential task of a
name server is to answer queries using data in its zones. By design,
name servers can answer queries in a simple manner; the response can
always be generated using only local data, and either contains the
answer to the question or a referral to other name servers "closer" to
the desired information.

A given zone will be available from several name servers to insure its
availability in spite of host or communication link failure. By
administrative fiat, we require every zone to be available on at least
two servers, and many zones have more redundancy than that.

A given name server will typically support one or more zones, but this
gives it authoritative information about only a small section of the
domain tree. It may also have some cached non-authoritative data about
other parts of the tree. The name server marks its responses to queries
so that the requester can tell whether the response comes from
authoritative data or not.

<br>

## How the Database is Divided into Zones

The domain database is divided in two ways:

1. Class
2. Zones

The class partition is simple, just imagine each class as a seperate yet
parallel namespace tree.

Within a class, "cuts" are made between any two adjacent nodes. Each group
of connected nodes froms a "zone". The zone is authoritative for all names
in the connected region. Note that the "cuts" in the namespace tree may be
different for different classes.

The name of the node closest to the root node is often used to identify
the zone itself.

Generally, these cuts are made at points where different orginizations are
willing to take ownership of a subtree, or where an orginization wants to
make further internal partitions.

<br>

## Technical Considerations

The data that describes a zone has four major parts:

   - Authoritative data for all nodes within the zone

   - Data that defines the top node of the zone (can be thought of as part of the authoritative data)

   - Data that describes delegated subzones, i.e., cuts around the bottom of the zone

   - Data that allows access to name servers for subzones (sometimes called "glue" data)

All of this data is expressed in the form of RRs, so a zone can be
completely described in terms of a set of RRs. Whole zones can be
transferred between name servers by transferring the RRs, either carried
in a series of messages or by FTPing a master file which is a textual
representation.

The authoritative data for a zone is simply all of the RRs attached to
all of the nodes from the top node of the zone down to leaf nodes or
nodes above cuts around the bottom edge of the zone.

Though logically part of the authoritative data, the RRs that describe
the top node of the zone are especially important to the zone's
management. These RRs are of two types:

- Name Server (NS) RRs that list, one per RR, all of the servers for the zone

- A single SOA RR that describes zone management parameters

The RRs that describe cuts around the bottom of the zone are NS RRs that
name the servers for the subzones. Since the cuts are between nodes,
these RRs are NOT part of the authoritative data of the zone, and should
be exactly the same as the corresponding RRs in the top node of the
subzone. Since name servers are always associated with zone boundaries,
NS RRs are only found at nodes which are the top node of some zone. In
the data that makes up a zone, NS RRs are found at the top node of the
zone (and are authoritative) and at cuts around the bottom of the zone
(where they are not authoritative), but never in between.

One of the goals of the zone structure is that any zone have all the
data required to set up communications with the name servers for any
subzones. That is, parent zones have all the information needed to
access servers for their children zones. The NS RRs that name the
servers for subzones are often not enough for this task since they name
the servers, but do not give their addresses. In particular, if the
name of the name server is itself in the subzone, we could be faced with
the situation where the NS RRs tell us that in order to learn a name
server's address, we should contact the server using the address we wish
to learn. To fix this problem, a zone contains "glue" RRs which are not
part of the authoritative data, and are address RRs for the servers.
These RRs are only necessary if the name server's name is "below" the
cut, that is, under a subzone, and are only used as part of a referral response.

<br>

## Name Server Internals

<br>

### Queries and Responses

The principal activity of name servers is to answer standard queries.
Both the query and its response are carried in a standard message format
which is described in [RFC-1035](https://www.ietf.org/rfc/rfc1035.txt). The query contains a QTYPE, QCLASS,
and QNAME, which describe the types and classes of desired information
and the name of interest.

The way that the name server answers the query depends upon whether it
is operating in recursive mode or not:

   - The simplest mode for the server is non-recursive, since it
     can answer queries using only local information: the response
     contains an error, the answer, or a referral to some other
     server "closer" to the answer. All name servers must
     implement non-recursive queries.

   - The simplest mode for the client is recursive, since in this
     mode the name server acts in the role of a resolver and
     returns either an error or the answer, but never referrals.
     This service is optional in a name server, and the name server
     may also choose to restrict the clients which can use
     recursive mode.

Recursive service is helpful in several situations:

   - a relatively simple requester that lacks the ability to use
     anything other than a direct answer to the question.

   - a request that needs to cross protocol or other boundaries and
     can be sent to a server which can act as intermediary.

   - a network where we want to concentrate the cache rather than
     having a separate cache for each client.

Non-recursive service is appropriate if the requester is capable of
pursuing referrals and interested in information which will aid future
requests.

The use of recursive mode is limited to cases where both the client and
the name server agree to its use. The agreement is negotiated through
the use of two bits in query and response messages:

   - The Recursion Available (RA) bit is set or cleared by a
     name server in all responses. The bit is true if the name
     server is willing to provide recursive service for the client,
     regardless of whether the client requested recursive service.
     That is, RA signals availability rather than use.

   - The Recursion Desired (RD) bit is set or cleared by a client in all queries. This
     bit specifies specifies whether the requester wants recursive
     service for this query. Clients may request recursive service
     from any name server, though they should depend upon receiving
     it only from servers which have previously sent an RA, or
     servers which have agreed to provide service through private
     agreement or some other means outside of the DNS protocol.

The recursive mode occurs when a query with RD set arrives at a server
which is willing to provide recursive service; the client can verify
that recursive mode was used by checking that both RA and RD are set in
the reply. Note that the name server should never perform recursive
service unless asked via RD, since this interferes with trouble shooting
of name servers and their databases.

If recursive service is requested and available, the recursive response
to a query will be one of the following:

   - The answer to the query, possibly preface by one or more CNAME
     RRs that specify aliases encountered on the way to an answer.

   - A name error indicating that the name does not exist. This
     may include CNAME RRs that indicate that the original query
     name was an alias for a name which does not exist.

   - A temporary error indication.

If recursive service is not requested or is not available, the non-
recursive response will be one of the following:

   - An authoritative name error indicating that the name does not
     exist.

   - A temporary error indication.

   - Some combination of:

     RRs that answer the question, together with an indication
     whether the data comes from a zone or is cached.

     A referral to name servers which have zones which are closer
     ancestors to the name than the server sending the reply.

   - RRs that the name server thinks will prove useful to the
     requester.


<br>

### Name Server Algorithm

The actual algorithm used by the name server will depend on the local OS
and data structures used to store RRs. The following algorithm assumes
that the RRs are organized in several tree structures, one for each
zone, and another for the cache:

   1. Set or clear the value of recursion available in the response
      depending on whether the name server is willing to provide
      recursive service. If recursive service is available and
      requested via the RD bit in the query, go to step 5,
      otherwise step 2.

   2. Search the available zones for the zone which is the nearest
      ancestor to QNAME. If such a zone is found, go to step 3,
      otherwise step 4.

   3. Start matching down, label by label, in the zone. The
      matching process can terminate several ways:

         a. If the whole of QNAME is matched, we have found the
            node.

            If the data at the node is a CNAME, and QTYPE doesn't
            match CNAME, copy the CNAME RR into the answer section
            of the response, change QNAME to the canonical name in
            the CNAME RR, and go back to step 1.

            Otherwise, copy all RRs which match QTYPE into the
            answer section and go to step 6.

         b. If a match would take us out of the authoritative data,
            we have a referral. This happens when we encounter a
            node with NS RRs marking cuts along the bottom of a
            zone.

            Copy the NS RRs for the subzone into the authority
            section of the reply. Put whatever addresses are
            available into the additional section, using glue RRs
            if the addresses are not available from authoritative
            data or the cache. Go to step 4.

         c. If at some label, a match is impossible (i.e., the
            corresponding label does not exist), look to see if a
            the * label exists.

            If the "\*" label does not exist, set an authoritative name
            error in the response and exit. Otherwise just exit.

            If the "\*" label does exist, match RRs at that node
            against QTYPE. If any match, copy them into the answer
            section, but set the owner of the RR to be QNAME or the name of the CNAME we have followed, and
            not the node with the "\*" label. Go to step 6.

   4. Start matching down in the cache. If QNAME is found in the
      cache, copy all RRs attached to it that match QTYPE into the
      answer section. If there was no delegation from
      authoritative data, look for the best one from the cache, and
      put it in the authority section. Go to step 6.

   5. Using the local resolver or a copy of its algorithm (see
      resolver section of this memo) to answer the query. Store
      the results, including any intermediate CNAMEs, in the answer
      section of the response.

   6. Using local data only, attempt to add other RRs which may be
      useful to the additional section of the query. Exit.

<br>

### Wildcards

In the previous algorithm, special treatment was given to RRs with owner
names starting with the label *. Such RRs are called wildcards.
Wildcard RRs can be thought of as instructions for synthesizing RRs.
When the appropriate conditions are met, the name server creates RRs
with an owner name equal to the query name and contents taken from the
wildcard RRs.

This facility is most often used to create a zone which will be used to
forward mail from the Internet to some other mail system. The general
idea is that any name in that zone which is presented to server in a
query will be assumed to exist, with certain properties, unless explicit
evidence exists to the contrary. Note that the use of the term zone
here, instead of domain, is intentional; such defaults do not propagate
across zone boundaries, although a subzone may choose to achieve that
appearance by setting up similar defaults.

The contents of the wildcard RRs follows the usual rules and formats for
RRs. The wildcards in the zone have an owner name that controls the
query names they will match. The owner name of the wildcard RRs is of
the form "\*.\<anydomain\>", where \<anydomain\> is any domain name.
\<anydomain\> should not contain other "\*" labels, and should be in the
authoritative data of the zone. The wildcards potentially apply to
descendants of \<anydomain\>, but not to \<anydomain\> itself. Another way
to look at this is that the "\*" label always matches at least one whole
label and sometimes more, but always whole labels.

Wildcard RRs do not apply:

   - When the query is in another zone. That is, delegation cancels
     the wildcard defaults.

   - When the query name or a name between the wildcard domain and
     the query name is known to exist. For example, if a wildcard
     RR has an owner name of \*.X, and the zone also contains RRs
     attached to B.X, the wildcards would apply to queries for name
     Z.X (presuming there is no explicit information for Z.X), but
     not to B.X, A.B.X, or X.

A "\*" label appearing in a query name has no special effect, but can be
used to test for wildcards in an authoritative zone; such a query is the
only way to get a response containing RRs with an owner name with \"*" in
it. The result of such a query should not be cached.

Note that the contents of the wildcard RRs are not modified when used to
synthesize RRs.

To illustrate the use of wildcard RRs, suppose a large company with a
large, non-IP/TCP, network wanted to create a mail gateway. If the
company was called X.COM, and IP/TCP capable gateway machine was called
A.X.COM, the following RRs might be entered into the COM zone:

    X.COM           MX      10      A.X.COM

    *.X.COM         MX      10      A.X.COM

    A.X.COM         A       1.2.3.4
    A.X.COM         MX      10      A.X.COM

    *.A.X.COM       MX      10      A.X.COM

This would cause any MX query for any domain name ending in X.COM to
return an MX RR pointing at A.X.COM. Two wildcard RRs are required
since the effect of the wildcard at \*.X.COM is inhibited in the A.X.COM
subtree by the explicit data for A.X.COM. Note also that the explicit
MX data at X.COM and A.X.COM is required, and that none of the RRs above
would match a query name of XX.COM.

<br>

### Negative Response Caching

Originally, negative response caching was an optional behaviour
for recursive and authoritative name servers. However, [RFC-2308](https://www.ietf.org/rfc/rfc2308.txt) clarified this behavior and made it mandatory.

The most common negative responses indicate that a particular RRset
does not exist in the DNS. The first sections of this document deal
with this case. Other negative responses can indicate failures of a
nameserver, those are dealt with in the Other Negative Responses section.

A negative response is indicated by one of the following conditions:

1. Name Error (NXDOMAIN)
2. No Data (NODATA)

<br>

#### Name Error (NXDOMAIN)

Name errors (NXDOMAIN) are indicated by the presence of "Name Error"
in the RCODE field. In this case the domain referred to by the QNAME
does not exist. Note: the answer section may have RRSIG and CNAME RRs
and the authority section may have SOA, NSEC, and RRSIG RRs.

It is possible to distinguish between a referral and a NXDOMAIN
response by the presense of NXDOMAIN in the RCODE regardless of the
presence of NS or SOA records in the authority section.

NXDOMAIN responses can be categorised into four types by the contents
of the authority section. These are shown below along with a
referral for comparison. Fields not mentioned are not important in
terms of the examples.

    NXDOMAIN RESPONSE: TYPE 1.

    Header:
        RDCODE=NXDOMAIN
    Query:
        AN.EXAMPLE. A
    Answer:
        AN.EXAMPLE. CNAME TRIPPLE.XX.
    Authority:
        XX. SOA NS1.XX. HOSTMASTER.NS1.XX. ....
        XX. NS NS1.XX.
        XX. NS NS2.XX.
    Additional:
        NS1.XX. A 127.0.0.2
        NS2.XX. A 127.0.0.3

    NXDOMAIN RESPONSE: TYPE 2.

    Header:
        RDCODE=NXDOMAIN
    Query:
        AN.EXAMPLE. A
    Answer:
        AN.EXAMPLE. CNAME TRIPPLE.XX.
    Authority:
        XX. SOA NS1.XX. HOSTMASTER.NS1.XX. ....
    Additional:
        <empty>

    NXDOMAIN RESPONSE: TYPE 3.

    Header:
        RDCODE=NXDOMAIN
    Query:
        AN.EXAMPLE. A
    Answer:
        AN.EXAMPLE. CNAME TRIPPLE.XX.
    Authority:
        <empty>
    Additional:
        <empty>

    NXDOMAIN RESPONSE: TYPE 4

    Header:
        RDCODE=NXDOMAIN
    Query:
        AN.EXAMPLE. A
    Answer:
        AN.EXAMPLE. CNAME TRIPPLE.XX.
    Authority:
        XX. NS NS1.XX.
        XX. NS NS2.XX.
    Additional:
        NS1.XX. A 127.0.0.2
        NS2.XX. A 127.0.0.3

    REFERRAL RESPONSE.

    Header:
        RDCODE=NOERROR
    Query:
        AN.EXAMPLE. A
    Answer:
        AN.EXAMPLE. CNAME TRIPPLE.XX.
    Authority:
        XX. NS NS1.XX.
        XX. NS NS2.XX.
    Additional:
        NS1.XX. A 127.0.0.2
        NS2.XX. A 127.0.0.3

Note, in the four examples of NXDOMAIN responses, it is known that
the name "AN.EXAMPLE." exists, and has as its value a CNAME record.
The NXDOMAIN refers to "TRIPPLE.XX", which is then known not to
exist. On the other hand, in the referral example, it is shown that
"AN.EXAMPLE" exists, and has a CNAME RR as its value, but nothing is
known one way or the other about the existence of "TRIPPLE.XX", other
than that "NS1.XX" or "NS2.XX" can be consulted as the next step in
obtaining information about it.

Where no CNAME records appear, the NXDOMAIN response refers to the
name in the label of the RR in the question section.

<br>

#### No Data (NODATA)

NODATA is indicated by an answer with the RCODE set to NOERROR and no
relevant answers in the answer section. The authority section will
contain an SOA record, or there will be no NS records there.

NODATA responses have to be algorithmically determined from the
response's contents as there is no RCODE value to indicate NODATA.
In some cases to determine with certainty that NODATA is the correct
response it can be necessary to send another query.

The authority section may contain NSEC and RRSIG RRsets in addition to
NS and SOA records. CNAME and RRSIG records may exist in the answer
section.

It is possible to distinguish between a NODATA and a referral
response by the presence of a SOA record in the authority section or
the absence of NS records in the authority section.

NODATA responses can be categorised into three types by the contents
of the authority section. These are shown below along with a
referral for comparison. Fields not mentioned are not important in
terms of the examples.

    NODATA RESPONSE: TYPE 1.

    Header:
        RDCODE=NOERROR
    Query:
        ANOTHER.EXAMPLE. A
    Answer:
        <empty>
    Authority:
        EXAMPLE. SOA NS1.XX. HOSTMASTER.NS1.XX. ....
        EXAMPLE. NS NS1.XX.
        EXAMPLE. NS NS2.XX.
    Additional:
        NS1.XX. A 127.0.0.2
        NS2.XX. A 127.0.0.3

    NO DATA RESPONSE: TYPE 2.

    Header:
        RDCODE=NOERROR
    Query:
        ANOTHER.EXAMPLE. A
    Answer:
        <empty>
    Authority:
        EXAMPLE. SOA NS1.XX. HOSTMASTER.NS1.XX. ....
    Additional:
        <empty>

    NO DATA RESPONSE: TYPE 3.

    Header:
        RDCODE=NOERROR
    Query:
        ANOTHER.EXAMPLE. A
    Answer:
        <empty>
    Authority:
        <empty>
    Additional:
        <empty>

    REFERRAL RESPONSE.

    Header:
        RDCODE=NOERROR
    Query:
        ANOTHER.EXAMPLE. A
    Answer:
        <empty>
    Authority:
        EXAMPLE. NS NS1.XX.
        EXAMPLE. NS NS2.XX.
    Additional:
        NS1.XX. A 127.0.0.2
        NS2.XX. A 127.0.0.3

These examples, unlike the NXDOMAIN examples above, have no CNAME
records, however they could, in just the same way that the NXDOMAIN
examples did, in which case it would be the value of the last CNAME
(the QNAME) for which NODATA would be concluded.

<br>

#### Negative Answers from Authoritative Servers

Name servers authoritative for a zone MUST include the SOA record of
the zone in the authority section of the response when reporting an
NXDOMAIN or indicating that no data of the requested type exists.
This is required so that the response may be cached. The TTL of this
record is set from the minimum of the MINIMUM field of the SOA record
and the TTL of the SOA itself, and indicates how long a resolver may
cache the negative answer. The TTL SIG record associated with the
SOA record should also be trimmed in line with the SOA's TTL.

If the containing zone is signed, the SOA and appropriate
NSEC and RRSIG records MUST be added.

<br>

#### SOA Minimum Field

The SOA minimum field has been overloaded in the past to have three
different meanings, the minimum TTL value of all RRs in a zone, the
default TTL of RRs which did not contain a TTL value and the TTL of
negative responses.

Despite being the original defined meaning, the first of these, the
minimum TTL value of all RRs in a zone, has never in practice been
used and is hereby deprecated.

The second, the default TTL of RRs which contain no explicit TTL in
the master zone file, is relevant only at the primary server. After
a zone transfer all RRs have explicit TTLs and it is impossible to
determine whether the TTL for a record was explicitly set or derived
from the default after a zone transfer. Where a server does not
require RRs to include the TTL value explicitly, it should provide a
mechanism, not being the value of the MINIMUM field of the SOA
record, from which the missing TTL values are obtained. How this is
done is implementation dependent.

The Master File format (see Master File section) is extended to include
the following directive:

    $TTL <TTL> [comment]

All resource records appearing after the directive, and which do not
explicitly include a TTL value, have their TTL set to the TTL given
in the $TTL directive.

The remaining of the current meanings, of being the TTL to be used
for negative responses, is the new defined meaning of the SOA minimum
field.

<br>

#### Caching Negative Answers

Like normal answers negative answers have a time to live (TTL). As
there is no record in the answer section to which this TTL can be
applied, the TTL must be carried by another method. This is done by
including the SOA record from the zone in the authority section of
the reply. When the authoritative server creates this record its TTL
is taken from the minimum of the SOA.MINIMUM field and SOA's TTL.
This TTL decrements in a similar manner to a normal cached answer and
upon reaching zero (0) indicates the cached negative answer MUST NOT
be used again.

A negative answer that resulted from a name error (NXDOMAIN) should
be cached such that it can be retrieved and returned in response to
another query for the same \<QNAME, QCLASS\> that resulted in the
cached negative response.

A negative answer that resulted from a no data error (NODATA) should
be cached such that it can be retrieved and returned in response to
another query for the same \<QNAME, QTYPE, QCLASS\> that resulted in
the cached negative response.

The NXT record, if it exists in the authority section of a negative
answer received, MUST be stored such that it can be be located and
returned with SOA record in the authority section, as should any SIG
records in the authority section. For NXDOMAIN answers there is no
"necessary" obvious relationship between the NXT records and the
QNAME. The NXT record MUST have the same owner name as the query
name for NODATA responses.

Negative responses without SOA records SHOULD NOT be cached as there
is no way to prevent the negative responses looping forever between a
pair of servers even with a short TTL.

Despite the DNS forming a tree of servers, with various mis-
configurations it is possible to form a loop in the query graph, e.g.
two servers listing each other as forwarders, various lame server
configurations. Without a TTL count down a cache negative response
when received by the next server would have its TTL reset. This
negative indication could then live forever circulating between the
servers involved.

As with caching positive responses it is sensible for a resolver to
limit for how long it will cache a negative response as the protocol
supports caching for up to 68 years. Such a limit should not be
greater than that applied to positive answers and preferably be
tunable. Values of one to three hours have been found to work well
and would make sensible a default. Values exceeding one day have
been found to be problematic.

<br>

#### Negative Answers from the Cache

When a server, in answering a query, encounters a cached negative
response it MUST add the cached SOA record to the authority section
of the response with the TTL decremented by the amount of time it was
stored in the cache. This allows the NXDOMAIN / NODATA response to
time out correctly.

If a NXT record was cached along with SOA record it MUST be added to
the authority section. If a SIG record was cached along with a NXT
record it SHOULD be added to the authority section.

As with all answers coming from the cache, negative answers SHOULD
have an implicit referral built into the answer. This enables the
resolver to locate an authoritative source. An implicit referral is
characterised by NS records in the authority section referring the
resolver towards a authoritative source. NXDOMAIN types 1 and 4
responses contain implicit referrals as does NODATA type 1 response.

<br>

#### Other Negative Responses

Caching of other negative responses is not covered by any existing
RFC. There is no way to indicate a desired TTL in these responses.
Care needs to be taken to ensure that there are not forwarding loops.

<br>

##### Server Failure (OPTIONAL)

Server failures fall into two major classes. The first is where a
server can determine that it has been misconfigured for a zone. This
may be where it has been listed as a server, but not configured to be
a server for the zone, or where it has been configured to be a server
for the zone, but cannot obtain the zone data for some reason. This
can occur either because the zone file does not exist or contains
errors, or because another server from which the zone should have
been available either did not respond or was unable or unwilling to
supply the zone.

The second class is where the server needs to obtain an answer from
elsewhere, but is unable to do so, due to network failures, other
servers that don't reply, or return server failure errors, or
similar.

In either case a resolver MAY cache a server failure response. If it
does so it MUST NOT cache it for longer than five (5) minutes, and it
MUST be cached against the specific query tuple \<query name, type,
class, server IP address\>.

<br>

##### Dead / Unreachable Server (OPTIONAL)

Dead / Unreachable servers are servers that fail to respond in any
way to a query or where the transport layer has provided an
indication that the server does not exist or is unreachable. A
server may be deemed to be dead or unreachable if it has not
responded to an outstanding query within 120 seconds.

Examples of transport layer indications are:

  * ICMP error messages indicating host, net or port unreachable.
  * TCP resets
  * IP stack error messages providing similar indications to those above.

A server MAY cache a dead server indication. If it does so it MUST
NOT be deemed dead for longer than five (5) minutes. The indication
MUST be stored against query tuple \<query name, type, class, server
IP address\> unless there was a transport layer indication that the
server does not exist, in which case it applies to all queries to
that specific IP address.

# Resolvers

<br>

# DNS Packet Structure

    +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+

<br>

## Header Format

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   OPCODE  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field   | Description |
| -----   | ----------- |
| ID      | A 16 bit identifier assigned by the program that generates any kind of query. This identifier is copied the corresponding reply and can be used by the requester to match up replies to outstanding queries |
| QR      | A one bit field that specifies whether this message is a query (0), or a response (1) |
| OPCODE  | A four bit field that specifies kind of query in this message. This value is set by the originator of a query and copied into the response.<br>The values are:<br>0 \| A standard query (QUERY)<br>1 \| An inverse query (IQUERY) (Obsolete, see [RFC-3425](https://www.ietf.org/rfc/rfc3425.txt))<br>2 \| A server status request (STATUS)<br>3-15 \| Reserved for future use |
| AA      | Authoritative Answer - this bit is valid in responses, and specifies that the responding name server is an authority for the domain name in question section.<br><br>Note that the contents of the answer section may have multiple owner names because of aliases. The AA bit corresponds to the name which matches the query name, or the first owner name in the answer section |
| TC      | Truncation - specifies that this message was truncated due to length greater than that permitted on the transmission channel |
| RD      | Recursion Desired - this bit may be set in a query and is copied into the response. If RD is set, it directs the name server to pursue the query recursively. Recursive query support is optional |
| RA      | Recursion Available - this bit is set or cleared in a response, and denotes whether recursive query support is available in the name server |
| Z       | Reserved for future use. Must be zero in all queries and responses |
| RCODE   | Response code - this 4 bit field is set as part of responses to denote result. |
| QDCOUNT | An unsigned 16 bit integer specifying the number of entries in the question section |
| ANCOUNT | An unsigned 16 bit integer specifying the number of resource records in the answer section |
| NSCOUNT | An unsigned 16 bit integer specifying the number of name server resource records in the authority records section |
| ARCOUNT | An unsigned 16 bit integer specifying the number of resource records in the additional records section |

<br>

### RCODE Values

RCODE values are a 4 bit field set as part of responses. Each value has a specific meaning depending on the type of query, the QNAME, and what resource records were returned.

| RCODE | Name    | Description |
| ----- | ----    | ----------- |
|   0   | NOERROR | The query was successfull, and the QNAME exists but not necessarily the requested resource records. |
|   1   | FORMERR | The query was malformed, and thus rejected. |
|   2   | SERVFAIL | This has 2 meanings. The first meaning is that the name server failed to correctly respond to this query due to some issue. This can happen for a number of reasons, such as timeouts during recursion, or some exception was encountered. The other meaning is that the name server failed to validate the DNSSEC signed zone, thus the zone is considered BOGUS. |
|   3   | NXDOMAIN/NAMERROR | This response means that the domain name in the query does not exist. NOTE: This DOES NOT mean the resource record queried for doesn't exist, but specifically that the domain name itself doesn't exist. The only caveat to this is if there was a CNAME chain. This changes the meaning to instead imply that the resulting canonical name does not exist. |
|   4   | NOTIMPLEMENTED | The name server does not support the requested kind of query. |
|   5   | REFUSED | The name server refuses to perform the specified operation for policy reasons. For eample, a name server may not wish to provide the information to the particular requestor, or may not wish to perform an operation for a particular piece of data. |
| 6 - 15 | RESERVED | Reserved for future use. |


<br>

## Question Format

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field  | Description |
| -----  | ----------- |
| QNAME  | A domain name represented as a sequence of labels, where each label consists of a length octet followed by that number of octets. The domain name terminates with the zero length octet for the null label of the root. Note that this field may be an odd number of octets; no padding is used |
| QTYPE  | A two octet code which specifies the type of the query. The values for this field include all codes valid for a TYPE field, together with some more general codes which can match more than one type of RR |
| QCLASS | A two octet code that specifies the class of the query. For example, the QCLASS field is IN for the Internet |

<br>

## Resource Record Format

The answer, authority, and additional sections all share the same
format: a variable number of resource records, where the number of
records is specified in the corresponding count field in the header.
Each resource record has the following format:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field | Description |
| ----- | ----------- |
| NAME  | A \<domain-name\> to which this resource record pertains |
| TYPE  | Two octets containing one of the RR type codes. This field specifies the meaning of the data in the RDATA field |
| CLASS | Two octets which specify the class of the data in the RDATA field |
| TTL   | A 32 bit unsigned integer that specifies the time interval (in seconds) that the resource record may be cached before it should be discarded. Zero values are interpreted to mean that the RR can only be used for the transaction in progress, and should not be cached |
| RDLENGTH | An unsigned 16 bit integer that specifies the length in octets of the RDATA field |
| RDATA | A variable length string of octets that describes the resource. The format of this information varies according to the TYPE and CLASS of the resource record. For example,   if the TYPE is A and the CLASS is IN, the RDATA field is a 4 octet ARPA Internet address |

<br>

## CLASS Values

CLASS fields appear in resource records. The following CLASS mnemonics
and values are defined:

| TYPE  | Value | Description |
| ----  | ----- | ----------- |
| IN    |   1   | The Internet class |
| CS    |   2   | The CSNET class (Obsolete - used only for examples in some obsolete RFCs)|
| CH    |   3   | The CHAOS class |
| HS    |   4   | The HESIOD [Dyer 87] class |

<br>

## QCLASS Values

QCLASS fields appear in the question section of a query. QCLASS values
are a superset of CLASS values; every CLASS is a valid QCLASS. In
addition to CLASS values, the following QCLASSes are defined:

| TYPE  | Value | Description |
| ----  | ----- | ----------- |
| *     |  255  | Any class |

<br>

## TYPE Values

TYPE fields are used in resource records. Note that these types are a
subset of QTYPEs.

| TYPE  | Value | Description |
| ----  | ----- | ----------- |
| A     |   1   | An IPv4 host address |
| NS    |   2   | An authoritative name server |
| MD    |   3   | A mail destination (Obsolete - use MX) |
| MF    |   4   | A mail forwarder (Obsolete - use MX) |
| CNAME |   5   | The canonical name for an alias |
| SOA   |   6   | Marks the start of a zone of authority |
| MB    |   7   | A mailbox domain name (EXPERIMENTAL) |
| MG    |   8   | A mail group member (EXPERIMENTAL) |
| MR    |   9   | A mail rename domain name (EXPERIMENTAL) |
| NULL  |   10  | A null RR (EXPERIMENTAL) |
| WKS   |   11  | A well known service description |
| PTR   |   12  | A domain name pointer |
| HINFO |   13  | Host information |
| MINFO |   14  | Mailbox or mail list information |
| MX    |   15  | Mail exchange |
| TXT   |   16  | Text strings |
| AAAA  |   28  | An IPv6 host address |
| SRV   |   33  | Specifies location of the servers for a specific protocol |

<br>

## QTYPE Values

QTYPE fields appear in the question part of a query. QTYPES are a
superset of TYPEs, hence all TYPEs are valid QTYPEs.<br>
In addition, the following QTYPEs are defined:

| QTYPE | Value | Description |
| ----- | ----- | ----------- |
| AXFR  |  252  | A request for a transfer of an entire zone |
| MAILB |  253  | A request for mailbox-related records (MB, MG, or MR) |
| MAILA |  254  | A request for mail agent RRs (Obsolete - see MX) |
| *     |  255  | A request for all records |

<br>

## Message Compression

In order to reduce the size of messages, the domain system utilizes a
compression scheme which eliminates the repetition of domain names in a
message. In this scheme, an entire domain name or a list of labels at
the end of a domain name is replaced with a pointer to a prior occurance
of the same name.

The pointer takes the form of a two octet sequence:

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | 1  1|                OFFSET                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

The first two bits are ones. This allows a pointer to be distinguished
from a label, since the label must begin with two zero bits because
labels are restricted to 63 octets or less. (The 10 and 01 combinations
are reserved for future use.)  The OFFSET field specifies an offset from
the start of the message (i.e., the first octet of the ID field in the
domain header). A zero offset specifies the first byte of the ID field,
etc.

The compression scheme allows a domain name in a message to be
represented as either:

   - a sequence of labels ending in a zero octet

   - a pointer

   - a sequence of labels ending with a pointer

Pointers can only be used for occurances of a domain name where the
format is not class specific. If this were not the case, a name server
or resolver would be required to know the format of all RRs it handled.
As yet, there are no such cases, but they may occur in future RDATA
formats.

If a domain name is contained in a part of the message subject to a
length field (such as the RDATA section of an RR), and compression is
used, the length of the compressed name is used in the length
calculation, rather than the length of the expanded name.

Programs are free to avoid using pointers in messages they generate,
although this will reduce datagram capacity, and may cause truncation.
However all programs are required to understand arriving messages that
contain pointers.

For example, a datagram might need to use the domain names F.ISI.ARPA,
FOO.F.ISI.ARPA, ARPA, and the root. Ignoring the other fields of the
message, these domain names might be represented as:

       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    20 |           1           |           F           |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    22 |           3           |           I           |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    24 |           S           |           I           |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    26 |           4           |           A           |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    28 |           R           |           P           |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    30 |           A           |           0           |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                              ...
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    40 |           3           |           F           |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    42 |           O           |           O           |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    44 | 1  1|                20                       |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                              ...
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    64 | 1  1|                26                       |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                              ...
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    92 |           0           |                       |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

The domain name for F.ISI.ARPA is shown at offset 20. The domain name
FOO.F.ISI.ARPA is shown at offset 40; this definition uses a pointer to
concatenate a label for FOO to the previously defined F.ISI.ARPA. The
domain name ARPA is defined at offset 64 using a pointer to the ARPA
component of the name F.ISI.ARPA at 20; note that this pointer relies on
ARPA being the last label in the string at 20. The root domain name is
defined by a single octet of zeros at 92; the root domain name has no
labels.

<br>

# Standard Resource Records RDATA (All classes)

The following RR definitions are expected to occur, at least
potentially, in all classes. In particular, NS, SOA, CNAME, and PTR
will be used in all classes, and have the same format in all classes.
Because their RDATA format is known, all domain names in the RDATA
section of these RRs may be compressed.

\<domain-name\> is a domain name represented as a series of labels, and
terminated by a label with zero length. \<character-string\> is a single
length octet followed by that number of characters. \<character-string\>
is treated as binary information, and can be up to 256 characters in
length (including the length octet).

<br>

## CNAME RDATA Format (RR TYPE 5)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     CNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field | Description |
| ----- | ----------- |
| CNAME | A \<domain-name\> which specifies the canonical or primary name for the owner. The owner name is an alias |

CNAME RRs cause no additional section processing, but name servers may
choose to restart the query at the canonical name in certain cases. See
the description of name server logic in [RFC-1034](https://www.ietf.org/rfc/rfc1034.txt) for details.

<br>

## HINFO RDATA Format (RR TYPE 13)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                      CPU                      /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                       OS                      /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field | Description |
| ----- | ----------- |
| CPU   | A \<character-string\> which specifies the CPU type |
| OS    | A \<character-string\> which specifies the operating system type |

Standard values for CPU and OS can be found in [RFC-1010](https://www.ietf.org/rfc/rfc1010.txt).

HINFO records are used to acquire general information about a host. The
main use is for protocols such as FTP that can use special procedures
when talking between machines or operating systems of the same type.

<br>

## MB RDATA Format (EXPERIMENTAL) (RR TYPE 7)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   MADNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field   | Description |
| -----   | ----------- |
| MADNAME | A \<domain-name\> which specifies a host which has the specified mailbox |

MB records cause additional section processing which looks up an A type
RRs corresponding to MADNAME.

## MD RDATA Format (OBSOLETE)  (RR TYPE 3)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   MADNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field   | Description |
| -----   | ----------- |
| MADNAME | A \<domain-name\> which specifies a host which has a mail agent for the domain which should be able to deliver mail for the domain |

MD records cause additional section processing which looks up an A type
record corresponding to MADNAME.

MD is obsolete. See the definition of MX and [RFC-974](https://www.ietf.org/rfc/rfc974.txt) for details of
the new scheme. The recommended policy for dealing with MD RRs found in
a master file is to reject them, or to convert them to MX RRs with a
preference of 0.

<br>

## MF RDATA Format (OBSOLETE) (RR TYPE 4)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   MADNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field   | Description |
| -----   | ----------- |
| MADNAME | A \<domain-name\> which specifies a host which has a mail agent for the domain which will accept mail for forwarding to the domain |

MF records cause additional section processing which looks up an A type
record corresponding to MADNAME.

MF is obsolete. See the definition of MX and [RFC-974](https://www.ietf.org/rfc/rfc974.txt) for details ofw
the new scheme. The recommended policy for dealing with MD RRs found in
a master file is to reject them, or to convert them to MX RRs with a
preference of 10.

<br>

## MG RDATA Format (EXPERIMENTAL) (RR TYPE 8)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   MGMNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field   | Description |
| -----   | ----------- |
| MGMNAME | A \<domain-name\> which specifies a mailbox which is a member of the mail group specified by the domain name |

MG records cause no additional section processing.

<br>

## MINFO RDATA Format (EXPERIMENTAL) (RR TYPE 14)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                    RMAILBX                    /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                    EMAILBX                    /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field   | Description |
| -----   | ----------- |
| RMAILBX | A \<domain-name\> which specifies a mailbox which is responsible for the mailing list or mailbox. If this domain name names the root, the owner of the MINFO RR is responsible for itself. Note that many existing mailing lists use a mailbox X-request for the RMAILBX field of mailing list X, e.g., Msgroup-request for Msgroup. This field provides a more general mechanism.
| EMAILBX | A \<domain-name\> which specifies a mailbox which is to receive error messages related to the mailing list or mailbox specified by the owner of the MINFO RR (similar to the ERRORS-TO: field which has been proposed). If this domain name names the root, errors should be returned to the sender of the message.

MINFO records cause no additional section processing. Although these
records can be associated with a simple mailbox, they are usually used
with a mailing list.

<br>

## MR RDATA Format (EXPERIMENTAL) (RR TYPE 9)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   NEWNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field   | Description |
| -----   | ----------- |
| NEWNAME | A \<domain-name\> which specifies a mailbox which is the proper rename of the specified mailbox |

MR records cause no additional section processing. The main use for MR
is as a forwarding entry for a user who has moved to a different
mailbox.

<br>

## MX RDATA Format (RR TYPE 15)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                  PREFERENCE                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   EXCHANGE                    /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field      | Description |
| -----      | ----------- |
| PREFERENCE | A 16 bit integer which specifies the preference given to this RR among others at the same owner. Lower values are preferred |
| EXCHANGE   | A \<domain-name\> which specifies a host willing to act as a mail exchange for the owner name |

MX records cause type A and AAAA additional section processing for the host
specified by EXCHANGE. The use of MX RRs is explained in detail in
[RFC-974](https://www.ietf.org/rfc/rfc974.txt).

<br>

## NULL RDATA Format (EXPERIMENTAL) (RR TYPE 10)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                  <anything>                   /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

Anything at all may be in the RDATA field so long as it is 65535 octets
or less.

NULL records cause no additional section processing. NULL RRs are not
allowed in master files. NULLs are used as placeholders in some
experimental extensions of the DNS.

<br>

## NS RDATA Format (RR TYPE 2)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   NSDNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field   | Description |
| -----   | ----------- |
| NSDNAME | A \<domain-name\> which specifies a host which should be authoritative for the specified class and domain |

NS records cause both the usual additional section processing to locate
a type A or AAAA record, and, when used in a referral, a special search of the
zone in which they reside for glue information.

The NS RR states that the named host should be expected to have a zone
starting at owner name of the specified class. Note that the class may
not indicate the protocol family which should be used to communicate
with the host, although it is typically a strong hint. For example,
hosts which are name servers for either Internet (IN) or Hesiod (HS)
class information are normally queried using IN class protocols.

<br>

## PTR RDATA Format (RR TYPE 12)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   PTRDNAME                    /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field    | Description |
| -----    | ----------- |
| PTRDNAME | A \<domain-name\> which points to some location in the domain name space |

PTR records cause no additional section processing. These RRs are used
in special domains to point to some other location in the domain space.
These records are simple data, and don't imply any special processing
similar to that performed by CNAME, which identifies aliases. See the
description of the IN-ADDR.ARPA domain for an example.

<br>

## SOA RDATA Format (RR TYPE 6)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     MNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     RNAME                     /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    SERIAL                     |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    REFRESH                    |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     RETRY                     |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    EXPIRE                     |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    MINIMUM                    |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field      | Description |
| -----      | ----------- |
| MNAME   | The \<domain-name\> of the name server that was the original or primary source of data for this zone |
| RNAME   | A \<domain-name\> which specifies the mailbox of the person responsible for this zone |
| SERIAL  | The unsigned 32 bit version number of the original copy of the zone. Zone transfers preserve this value. This value wraps and should be compared using sequence space arithmetic |
| REFRESH | A 32 bit time interval before the zone should be refreshed |
| RETRY   | A 32 bit time interval that should elapse before a failed refresh should be retried |
| EXPIRE  | A 32 bit time value that specifies the upper limit on the time interval that can elapse before the zone is no longer authoritative |
| MINIMUM | The unsigned 32 bit minimum TTL field that should be exported with any RR from this zone |

SOA records cause no additional section processing.

All times are in units of seconds.

Most of these fields are pertinent only for name server maintenance
operations. However, MINIMUM is used in negative response caching.
Whenever a query is made for a record or name that does not exist,
an SOA record for that zone can be included in the response. In this
situation the MINIMUM field is to be interpreted as the TTL for caching
the non-existence of the record or domain name. For more details, see
Negative Response Caching section.

<br>

## TXT RDATA format (RR TYPE 16)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   TXT-DATA                    /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field    | Description |
| -----    | ----------- |
| TXT-DATA | One or more \<character-string\>s |

TXT RRs are used to hold descriptive text. The semantics of the text
depends on the domain where it is found.

<br>

## SRV RDATA Format (RR TYPE 33)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    Priority                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     Weight                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      Port                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     Target                    /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field    | Description |
| -----    | ----------- |
| Priority | As for MX, the priority of this target host. A client MUST attempt to contact the target host with the lowest-numbered priority it can reach; target hosts with the same priority SHOULD be tried in pseudorandom order |
| Weight   | Load balancing mechanism. When selecting a target host among the those that have the same priority, the chance of trying this one first SHOULD be proportional to its weight. Domain administrators are urged to use Weight 0 when there isn't any load balancing to do, to make the RR easier to read for humans (less noisy) |
| Port     | The port on this target host of this service. This is often as specified in Assigned Numbers but need not be |
| Target   | The \<domain-name\> of the target host. There MUST be one or more A records for this name. Implementors are urged, but not required, to return the A record(s) in the Additional Data section. Name compression is to be used for this field.<br><br>A Target of "." means that the service is decidedly not available at this domain |

<br>The textual representation of a SRV RR is the following:<br>
_Service._Proto.Name TTL Class SRV Priority Weight Port Target

This means that the name for a specific service under a domain is somewhat counter-intuitive.
For example, if a browser wished to retrieve the corresponding server for `http://www.asdf.com/`, then it would make a lookup of QNAME=_http._tcp.www.asdf.com., QTYPE=33, QCLASS=1. The response would look something like:<br>

    _http._tcp.www.asdf.com. 600 1 SRV 1 0 443 website.asdf.com.

<br>

#  Internet Specific Resource Records RDATA (IN class)

## A RDATA Format (RR TYPE 1)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ADDRESS                    |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field   | Description |
| -----   | ----------- |
| ADDRESS | A 32 bit IPv4 address |

Hosts that have multiple IPv4 addresses will have multiple A
records.

A records cause no additional section processing. The RDATA section of
an A line in a master file is an IPv4 address expressed as four
decimal numbers separated by dots without any imbedded spaces (e.g.,
"10.2.0.52" or "192.0.5.6").

<br>

## AAAA RDATA Format (RR TYPE 28)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    |                                               |
    |                                               |
    |                   ADDRESS                     |
    |                                               |
    |                                               |
    |                                               |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field   | Description |
| -----   | ----------- |
| ADDRESS | A 128 bit IPv6 address in network byte order (high-order byte first) |

Hosts that have muiltiple IPv6 addresses will have multiple AAAA records

AAAA records cause no additional section processing. The RDATA section of
an A line in a master file is an IPv6 address expressed as a standard
IPv6 address (e.g., 4321:0:1:2:3:4:567:89ab).

<br>

## WKS RDATA Format (RR TYPE 11)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ADDRESS                    |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |       PROTOCOL        |                       |
    +--+--+--+--+--+--+--+--+                       |
    |                                               |
    /                   <BIT MAP>                   /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field       | Description |
| -----       | ----------- |
| ADDRESS     | An 32 bit Internet address |
| PROTOCOL    | An 8 bit IP protocol number |
| \<BIT MAP\> | A variable length bit map. The bit map must be a multiple of 8 bits long |

The WKS record is used to describe the well known services supported by
a particular protocol on a particular internet address. The PROTOCOL
field specifies an IP protocol number, and the bit map has one bit per
port of the specified protocol. The first bit corresponds to port 0,
the second to port 1, etc. If the bit map does not include a bit for a
protocol of interest, that bit is assumed zero. The appropriate values
and mnemonics for ports and protocols are specified in [RFC-1010](https://www.ietf.org/rfc/rfc1010.txt).

For example, if PROTOCOL=TCP (6), the 26th bit corresponds to TCP port
25 (SMTP). If this bit is set, a SMTP server should be listening on TCP
port 25; if zero, SMTP service is not supported on the specified
address.

The purpose of WKS RRs is to provide availability information for
servers for TCP and UDP. If a server supports both TCP and UDP, or has
multiple Internet addresses, then multiple WKS RRs are used.

WKS RRs cause no additional section processing.

In master files, both ports and protocols are expressed using mnemonics
or decimal numbers.

<br>

# IN-ADDR.ARPA Domain

The Internet uses a special domain to support gateway location and
Internet address to host mapping. Other classes may employ a similar
strategy in other domains. The intent of this domain is to provide a
guaranteed method to perform host address to host name mapping, and to
facilitate queries to locate all gateways on a particular network in the
Internet.

Note that both of these services are similar to functions that could be
performed by inverse queries; the difference is that this part of the
domain name space is structured according to address, and hence can
guarantee that the appropriate data can be located without an exhaustive
search of the domain space.

The domain begins at IN-ADDR.ARPA and has a substructure which follows
the Internet addressing structure.

Domain names in the IN-ADDR.ARPA domain are defined to have up to four
labels in addition to the IN-ADDR.ARPA suffix. Each label represents
one octet of an Internet address, and is expressed as a character string
for a decimal value in the range 0-255 (with leading zeros omitted
except in the case of a zero octet which is represented by a single
zero).

Host addresses are represented by domain names that have all four labels
specified. Thus data for Internet address 10.2.0.52 is located at
domain name 52.0.2.10.IN-ADDR.ARPA. The reversal, though awkward to
read, allows zones to be delegated which are exactly one network of
address space. For example, 10.IN-ADDR.ARPA can be a zone containing
data for the ARPANET, while 26.IN-ADDR.ARPA can be a separate zone for
MILNET. Address nodes are used to hold pointers to primary host names
in the normal domain space.

Network numbers correspond to some non-terminal nodes at various depths
in the IN-ADDR.ARPA domain, since Internet network numbers are either 1,
2, or 3 octets. Network nodes are used to hold pointers to the primary
host names of gateways attached to that network. Since a gateway is, by
definition, on more than one network, it will typically have two or more
network nodes which point at it. Gateways will also have host level
pointers at their fully qualified addresses.

Both the gateway pointers at network nodes and the normal host pointers
at full address nodes use the PTR RR to point back to the primary domain
names of the corresponding hosts.

For example, the IN-ADDR.ARPA domain will contain information about the
ISI gateway between net 10 and 26, an MIT gateway from net 10 to MIT's
net 18, and A<nolink>.ISI.EDU and MULTICS<nolink>.MIT.EDU. Assuming that ISI
gateway has addresses 10.2.0.22 and 26.0.0.103, and a name MILNET-
GW<nolink>.ISI.EDU, and the MIT gateway has addresses 10.0.0.77 and 18.10.0.4
and a name GW<nolink>.LCS.MIT.EDU, the domain database would contain:

    10.IN-ADDR.ARPA.            PTR   MILNET-GW.ISI.EDU.
    10.IN-ADDR.ARPA.            PTR   GW.LCS.MIT.EDU.
    18.IN-ADDR.ARPA.            PTR   GW.LCS.MIT.EDU.
    26.IN-ADDR.ARPA.            PTR   MILNET-GW.ISI.EDU.
    22.0.2.10.IN-ADDR.ARPA.     PTR   MILNET-GW.ISI.EDU.
    103.0.0.26.IN-ADDR.ARPA.    PTR   MILNET-GW.ISI.EDU.
    77.0.0.10.IN-ADDR.ARPA.     PTR   GW.LCS.MIT.EDU.
    4.0.10.18.IN-ADDR.ARPA.     PTR   GW.LCS.MIT.EDU.
    103.0.3.26.IN-ADDR.ARPA.    PTR   A.ISI.EDU.
    6.0.0.10.IN-ADDR.ARPA.      PTR   MULTICS.MIT.EDU.

Thus a program which wanted to locate gateways on net 10 would originate
a query of the form QTYPE=PTR, QCLASS=IN, QNAME=10.IN-ADDR.ARPA. It
would receive two RRs in response:

    10.IN-ADDR.ARPA.            PTR   MILNET-GW.ISI.EDU.
    10.IN-ADDR.ARPA.            PTR   GW.LCS.MIT.EDU.

The program could then originate QTYPE=A, QCLASS=IN queries for MILNET-
GW<nolink>.ISI.EDU. and GW<nolink>.LCS.MIT.EDU. to discover the Internet addresses of
these gateways.

A resolver which wanted to find the host name corresponding to Internet
host address 10.0.0.6 would pursue a query of the form QTYPE=PTR,
QCLASS=IN, QNAME=6.0.0.10.IN-ADDR.ARPA, and would receive:

    6.0.0.10.IN-ADDR.ARPA.      PTR   MULTICS.MIT.EDU.

Several cautions apply to the use of these services:
   - Since the IN-ADDR.ARPA special domain and the normal domain
     for a particular host or gateway will be in different zones,
     the possibility exists that that the data may be inconsistent.

   - Gateways will often have two names in separate domains, only
     one of which can be primary.

   - Systems that use the domain database to initialize their
     routing tables must start with enough gateway information to
     guarantee that they can access the appropriate name server.

   - The gateway data only reflects the existence of a gateway in a
     manner equivalent to the current HOSTS.TXT file. It doesn't
     replace the dynamic availability information from GGP or EGP.

<br>

# IP6.ARPA Domain

The IP6.ARPA domain provides an analogous purpose to IN-ADDR.ARPA.

Previously, in [RFC-1886](https://www.ietf.org/rfc/rfc1886.txt) the
domain IP6.INT was established. However, this was deprecated in [RFC-3152](https://www.ietf.org/rfc/rfc3152.txt)
in favor of IP6.ARPA. They both serve the same purpose.

In this domain, a resolver which wanted to find the host name corresponding to
Internet host address 4321:0:1:2:3:4:567:89ab would pursue a query of the form
QTYPE=PTR, QCLASS=IN, QNAME=b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.IP6.ARPA.,
and would receive:

    b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.IP6.ARPA.  PTR   MULTICS.MIT.EDU.