---
title: Domain Name System (DNS)
header-includes:
    <meta name="author" content="William Fleetwood" />
---

>**TODO**
>
>* Update to include DNSSEC
>* Update resource records section of document (sorting, missing RRs, merge sections)


# Introduction

This document describes the Domain Name System (DNS), including the design, server roles, algorithms, data, use cases, and on the wire message protocol that make up the DNS.
The DNS design and usage is defined in a large number of different RFCs starting back in 1983, many of which have been corrected, clarified, extended, updated, or made completely obsolete by more modern RFCs. This makes understanding the current DNS specifications in its entirety quite difficult and realistically impossible for most people.

In order to combat this issue, and thus make any future DNS development both easier and more accurate, this document attempts to compile all the relevent DNS RFCs into one single, up to date, clear, all encompassing document. Note that in the future, depending on the size of this document, it may be split up into multiple documents for readability.

For a complete list of DNS related RFCs, see [https://www.bind9.net/rfc](https://www.bind9.net/rfc).

Compiled RFCs:

* [RFC-1033](https://www.ietf.org/rfc/rfc1033.txt)
* [RFC-1034](https://www.ietf.org/rfc/rfc1034.txt)
* [RFC-1035](https://www.ietf.org/rfc/rfc1035.txt)
* [RFC-2308](https://www.ietf.org/rfc/rfc2308.txt)
* [RFC-3425](https://www.ietf.org/rfc/rfc3425.txt)
* (*TODO*) [RFC-4033](https://www.ietf.org/rfc/rfc4033.txt)
* (*TODO*) [RFC-4034](https://www.ietf.org/rfc/rfc4034.txt)
* (*TODO*) [RFC-4035](https://www.ietf.org/rfc/rfc4035.txt)
* (*TODO*) [RFC-6891](https://www.ietf.org/rfc/rfc6891.txt)

The following RFCs are only relevent to DNS management operations, or are better described in other RFCs, and thus do not affect DNS behavior itself:

* [RFC-881](https://www.ietf.org/rfc/rfc881.txt)
* [RFC-897](https://www.ietf.org/rfc/rfc897.txt)
* [RFC-921](https://www.ietf.org/rfc/rfc921.txt)
* [RFC-1032](https://www.ietf.org/rfc/rfc1032.txt)

This document and its source, as well as a DNS library written in Rust which uses this documentation as a source of truth, is hosted on [https://github.com/willfleetw/rusty_dns](https://github.com/willfleetw/rusty_dns).

A useful link for quickly looking up a given DNS related value or definition is: [Domain Name System (DNS) Parameters](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)



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



## Size Limits

Various objects and parameters in the DNS have size limits. They are
listed below. Some could be easily changed, others are more
fundamental.

| Parameter | Limit |
| --------- | ----- |
|  labels   | 63 octets or less |
|  names    | 255 octets or less |
|   TTL     | Positive values of a signed 32 bit number |
| UDP messages | 512 octets or less (EDNS allows for larger sizes) |



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



## Name Server Internals



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



#### Other Negative Responses

Caching of other negative responses is not covered by any existing
RFC. There is no way to indicate a desired TTL in these responses.
Care needs to be taken to ensure that there are not forwarding loops.



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



### Zone Maintenance and Transfers

Part of the job of a zone administrator is to maintain the zones at all
of the name servers which are authoritative for the zone. When the
inevitable changes are made, they must be distributed to all of the name
servers. While this distribution can be accomplished using FTP or some
other ad hoc procedure, the preferred method is the zone transfer part
of the DNS protocol.

The general model of automatic zone transfer or refreshing is that one
of the name servers is the master or primary for the zone. Changes are
coordinated at the primary, typically by editing a master file for the
zone. After editing, the administrator signals the master server to
load the new zone. The other non-master or secondary servers for the
zone periodically check for changes (at a selectable interval) and
obtain new zone copies when changes have been made.

To detect changes, secondaries just check the SERIAL field of the SOA
for the zone. In addition to whatever other changes are made, the
SERIAL field in the SOA of the zone is always advanced whenever any
change is made to the zone. The advancing can be a simple increment, or
could be based on the write date and time of the master file, etc. The
purpose is to make it possible to determine which of two copies of a
zone is more recent by comparing serial numbers. Serial number advances
and comparisons use sequence space arithmetic, so there is a theoretic
limit on how fast a zone can be updated, basically that old copies must
die out before the serial number covers half of its 32 bit range. In
practice, the only concern is that the compare operation deals properly
with comparisons around the boundary between the most positive and most
negative 32 bit numbers.

The periodic polling of the secondary servers is controlled by
parameters in the SOA RR for the zone, which set the minimum acceptable
polling intervals. The parameters are called REFRESH, RETRY, and
EXPIRE. Whenever a new zone is loaded in a secondary, the secondary
waits REFRESH seconds before checking with the primary for a new serial.
If this check cannot be completed, new checks are started every RETRY
seconds. The check is a simple query to the primary for the SOA RR of
the zone. If the serial field in the secondary's zone copy is equal to
the serial returned by the primary, then no changes have occurred, and
the REFRESH interval wait is restarted. If the secondary finds it
impossible to perform a serial check for the EXPIRE interval, it must
assume that its copy of the zone is obsolete an discard it.

When the poll shows that the zone has changed, then the secondary server
must request a zone transfer via an AXFR request for the zone. The AXFR
may cause an error, such as refused, but normally is answered by a
sequence of response messages. The first and last messages must contain

the data for the top authoritative node of the zone. Intermediate
messages carry all of the other RRs from the zone, including both
authoritative and non-authoritative RRs. The stream of messages allows
the secondary to construct a copy of the zone. Because accuracy is
essential, TCP or some other reliable protocol must be used for AXFR
requests.

Each secondary server is required to perform the following operations
against the master, but may also optionally perform these operations
against other secondary servers. This strategy can improve the transfer
process when the primary is unavailable due to host downtime or network
problems, or when a secondary server has better network access to an
"intermediate" secondary than to the primary.



# Resolvers

Resolvers are programs that interface user programs to domain name
servers. In the simplest case, a resolver receives a request from a
user program (e.g., mail programs, TELNET, FTP) in the form of a
subroutine call, system call etc., and returns the desired information
in a form compatible with the local host's data formats.

Because a resolver may need to consult several name
servers, or may have the requested information in a local cache, the
amount of time that a resolver will take to complete can vary quite a
bit, from milliseconds to several seconds.

A very important goal of the resolver is to eliminate network delay and
name server load from most requests by answering them from its cache of
prior results. It follows that caches which are shared by multiple
processes, users, machines, etc., are more efficient than non-shared
caches.



## Client-Resolver Interface



### Typical Functions

The client interface to the resolver is influenced by the local host's
conventions, but the typical resolver-client interface has three
functions:

   1. Host name to host address translation.

      This function is often defined to mimic a previous HOSTS.TXT
      based function. Given a character string, the caller wants
      one or more 32 bit IP addresses. Under the DNS, it
      translates into a request for type A RRs. Since the DNS does
      not preserve the order of RRs, this function may choose to
      sort the returned addresses or select the "best" address if
      the service returns only one choice to the client. Note that
      a multiple address return is recommended, but a single
      address may be the only way to emulate prior HOSTS.TXT
      services.

   2. Host address to host name translation

      This function will often follow the form of previous
      functions. Given a 32 bit IP address, the caller wants a
      character string. The octets of the IP address are reversed,
      used as name components, and suffixed with "IN-ADDR.ARPA". A
      type PTR query is used to get the RR with the primary name of
      the host. For example, a request for the host name
      corresponding to IP address 1.2.3.4 looks for PTR RRs for
      domain name "4.3.2.1.IN-ADDR.ARPA".

   3. General lookup function

      This function retrieves arbitrary information from the DNS,
      and has no counterpart in previous systems. The caller
      supplies a QNAME, QTYPE, and QCLASS, and wants all of the
      matching RRs. This function will often use the DNS format
      for all RR data instead of the local host's, and returns all
      RR content (e.g., TTL) instead of a processed form with local
      quoting conventions.

When the resolver performs the indicated function, it usually has one of
the following results to pass back to the client:

   - One or more RRs giving the requested data.

     In this case the resolver returns the answer in the
     appropriate format.

   - A name error (NXDOMAIN).

     This happens when the referenced name does not exist. For
     example, a user may have mistyped a host name.

   - A data not found error (NODATA).

     This happens when the referenced name exists, but data of the
     appropriate type does not. For example, a host address
     function applied to a mailbox name would return this error
     since the name exists, but no address RR is present.

It is important to note that the functions for translating between host
names and addresses may combine the "name error" and "data not found"
error conditions into a single type of error return, but the general
function should not. One reason for this is that applications may ask
first for one type of information about a name followed by a second
request to the same name for some other type of information; if the two
errors are combined, then useless queries may slow the application.



### Aliases

While attempting to resolve a particular request, the resolver may find
that the name in question is an alias. For example, the resolver might
find that the name given for host name to address translation is an
alias when it finds the CNAME RR. If possible, the alias condition
should be signalled back from the resolver to the client.

In most cases a resolver simply restarts the query at the new name when
it encounters a CNAME. However, when performing the general function,
the resolver should not pursue aliases when the CNAME RR matches the
query type. This allows queries which ask whether an alias is present.
For example, if the query type is CNAME, the user is interested in the
CNAME RR itself, and not the RRs at the name it points to.

Several special conditions can occur with aliases. Multiple levels of
aliases should be avoided due to their lack of efficiency, but should
not be signalled as an error. Alias loops and aliases which point to
non-existent names should be caught and an error condition passed back
to the client.



### Temporary Failures

In a less than perfect world, all resolvers will occasionally be unable
to resolve a particular request. This condition can be caused by a
resolver which becomes separated from the rest of the network due to a
link failure or gateway problem, or less often by coincident failure or
unavailability of all servers for a particular domain.

It is essential that this sort of condition should not be signalled as a
name or data not present error to applications. This sort of behavior
is annoying to humans, and can wreak havoc when mail systems use the
DNS.

While in some cases it is possible to deal with such a temporary problem
by blocking the request indefinitely, this is usually not a good choice,
particularly when the client is a server process that could move on to
other tasks. The recommended solution is to always have temporary
failure as one of the possible results of a resolver function, even
though this may make emulation of existing HOSTS.TXT functions more
difficult.



## Resolver Internals

Every resolver implementation uses slightly different algorithms, and
typically spends much more logic dealing with errors of various sorts
than typical occurances. This section outlines a recommended basic
strategy for resolver operation.



### Stub Resolvers

One option for implementing a resolver is to move the resolution
function out of the local machine and into a name server which supports
recursive queries. This can provide an easy method of providing domain
service in a PC which lacks the resources to perform the resolver
function, or can centralize the cache for a whole local network or
organization.

All that the remaining stub needs is a list of name server addresses
that will perform the recursive requests. This type of resolver
presumably needs the information in a configuration file, since it
probably lacks the sophistication to locate it in the domain database.
The user also needs to verify that the listed servers will perform the
recursive service; a name server is free to refuse to perform recursive
services for any or all clients. The user should consult the local
system administrator to find name servers willing to perform the
service.

This type of service suffers from some drawbacks. Since the recursive
requests may take an arbitrary amount of time to perform, the stub may
have difficulty optimizing retransmission intervals to deal with both
lost UDP packets and dead servers; the name server can be easily
overloaded by too zealous a stub if it interprets retransmissions as new
requests. Use of TCP may be an answer, but TCP may well place burdens
on the host's capabilities which are similar to those of a real
resolver.



### Resources

In addition to its own resources, the resolver may also have shared
access to zones maintained by a local name server. This gives the
resolver the advantage of more rapid access, but the resolver must be
careful to never let cached information override zone data. In this
discussion the term "local information" is meant to mean the union of
the cache and such shared zones, with the understanding that
authoritative data is always used in preference to cached data when both
are present.

The following resolver algorithm assumes that all functions have been
converted to a general lookup function, and uses the following data
structures to represent the state of a request in progress in the
resolver:

| Resource | Description |
| -------- | ----------- |
|  SNAME   | The domain name we are searching for |
|  STYPE   | The QTYPE of the search request |
|  SCLASS  | The QCLASS of the search request |
|  SLIST   | A structure which describes the name servers and the zone which the resolver is currently trying to query. This structure keeps track of the resolver's current best guess about which name servers hold the desired information; it is updated when arriving information changes the guess. This structure includes the equivalent of a zone name, the known name servers for the zone, the known addresses for the name servers, and history information which can be used to suggest which server is likely to be the best one to try next. The zone name equivalent is a match count of the number of labels from the root down which SNAME has in common with the zone being queried; this is used as a measure of how "close" the resolver is to SNAME |
|  SBELT   | A "safety belt" structure of the same form as SLIST, which is initialized from a configuration file, and lists servers which should be used when the resolver doesn't have any local information to guide name server selection. The match count will be -1 to indicate that no labels are known to match |
|  CACHE   | A structure which stores the results from previous responses. Since resolvers are responsible for discarding old RRs whose TTL has expired, most implementations convert the interval specified in arriving RRs to some sort of absolute time when the RR is stored in the cache. Instead of counting the TTLs down individually, the resolver just ignores or discards old RRs when it runs across them in the course of a search, or discards them during periodic sweeps to reclaim the memory consumed by old RRs |



### Algorithm

The top level algorithm has four steps:

   1. See if the answer is in local information, and if so return
      it to the client.

   2. Find the best servers to ask.

   3. Send them queries until one returns a response.

   4. Analyze the response, either:

         a. if the response answers the question or contains a name
            error, cache the data as well as returning it back to
            the client.

         b. if the response contains a better delegation to other
            servers, cache the delegation information, and go to
            step 2.

         c. if the response shows a CNAME and that is not the
            answer itself, cache the CNAME, change the SNAME to the
            canonical name in the CNAME RR and go to step 1.

         d. if the response shows a servers failure or other
            bizarre contents, delete the server from the SLIST and
            go back to step 3.

Step 1 searches the cache for the desired data. If the data is in the
cache, it is assumed to be good enough for normal use. Some resolvers
have an option at the user interface which will force the resolver to
ignore the cached data and consult with an authoritative server. This
is not recommended as the default. If the resolver has direct access to
a name server's zones, it should check to see if the desired data is
present in authoritative form, and if so, use the authoritative data in
preference to cached data.

NS RRs list the names of hosts for a zone at or above SNAME. Copy
the names into SLIST. Set up their addresses using local data. It may
be the case that the addresses are not available. The resolver has many
choices here; the best is to start parallel resolver processes looking
for the addresses while continuing onward with the addresses which are
available. Obviously, the design choices and options are complicated
and a function of the local host's capabilities. The recommended
priorities for the resolver designer are:

   1. Bound the amount of work (packets sent, parallel processes
      started) so that a request can't get into an infinite loop or
      start off a chain reaction of requests or queries with other
      implementations EVEN IF SOMEONE HAS INCORRECTLY CONFIGURED
      SOME DATA.

   2. Get back an answer if at all possible.

   3. Avoid unnecessary transmissions.

   4. Get the answer as quickly as possible.

If the search for NS RRs fails, then the resolver initializes SLIST from
the safety belt SBELT. The basic idea is that when the resolver has no
idea what servers to ask, it should use information from a configuration
file that lists several servers which are expected to be helpful.
Although there are special situations, the usual choice is two of the
root servers and two of the servers for the host's domain. The reason
for two of each is for redundancy. The root servers will provide
eventual access to all of the domain space. The two local servers will
allow the resolver to continue to resolve local names if the local
network becomes isolated from the internet due to gateway or link
failure.

In addition to the names and addresses of the servers, the SLIST data
structure can be sorted to use the best servers first, and to insure
that all addresses of all servers are used in a round-robin manner. The
sorting can be a simple function of preferring addresses on the local
network over others, or may involve statistics from past events, such as
previous response times and batting averages.

Step 3 sends out queries until a response is received. The strategy is
to cycle around all of the addresses for all of the servers with a
timeout between each transmission. In practice it is important to use
all addresses of a multihomed host, and too aggressive a retransmission
policy actually slows response when used by multiple resolvers
contending for the same name server and even occasionally for a single
resolver. SLIST typically contains data values to control the timeouts
and keep track of previous transmissions.

Step 4 involves analyzing responses. The resolver should be highly
paranoid in its parsing of responses. It should also check that the
response matches the query it sent using the ID field in the response.

The ideal answer is one from a server authoritative for the query which
either gives the required data or a name error. The data is passed back
to the user and entered in the cache for future use if its TTL is
greater than zero.

If the response shows a delegation, the resolver should check to see
that the delegation is "closer" to the answer than the servers in SLIST
are. This can be done by comparing the match count in SLIST with that
computed from SNAME and the NS RRs in the delegation. If not, the reply
is bogus and should be ignored. If the delegation is valid the NS
delegation RRs and any address RRs for the servers should be cached.
The name servers are entered in the SLIST, and the search is restarted.

If the response contains a CNAME, the search is restarted at the CNAME
unless the response has the data for the canonical name or if the CNAME
is the answer itself.



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



## CLASS Values

CLASS fields appear in resource records. The following CLASS mnemonics
and values are defined:

| TYPE  | Value | Description |
| ----  | ----- | ----------- |
| IN    |   1   | The Internet class |
| CS    |   2   | The CSNET class (Obsolete - used only for examples in some obsolete RFCs)|
| CH    |   3   | The CHAOS class |
| HS    |   4   | The HESIOD [Dyer 87] class |



## QCLASS Values

QCLASS fields appear in the question section of a query. QCLASS values
are a superset of CLASS values; every CLASS is a valid QCLASS. In
addition to CLASS values, the following QCLASSes are defined:

| TYPE  | Value | Description |
| ----  | ----- | ----------- |
| *     |  255  | Any class |

Note that unless explicitly stated otherwise, ALL QCLASS/CLASS values in this
document are assumed to be IN (1).

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



## Label Representation on-the-wire

Domain names consist of a series of labels. Many parts of the DNS message protocol
represent either full domain names, or individual labels. In either case, labels are
represented on-the-wire as a series of octets in one out of 4 ways:

Note: A label can consist of either an odd or even number of octets.

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | 0  0|     LENGTH      |                       |
    +--+--+--+--+--+--+--+--+                       +
    /                                               /
    /                   LENGTH BYTES                /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

The first two bits are `0b00`, the next 6 bits represent the number
of following octects. The rest of the octects represent the label.

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | 0  1|  EXTENDED TYPE  |                       |
    +--+--+--+--+--+--+--+--+                       +
    /             EXTENDED TYPE ENCODING            /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

The first two bits are `0b01`, the next 6 bits represent the encoding type of
the lable. The rest of the octects are dependent on the encoding type.

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | 1  1|                OFFSET                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

The first two bits are `0b11`, the next 14 bits represent an offset into the DNS
packet (see Section 5.8.2).



### Extended Label Types

[RFC-2671](https://www.ietf.org/rfc/rfc2671.txt) defined DNS label type 0b01 for use as an indication for
extended label types. A specific extended label type was selected by
the 6 least significant bits of the first octet. Thus, extended
label types were indicated by the values 64-127 (`0b01xxxxxx`) in the
first octet of the label.

Extended label types are extremely difficult to deploy due to lack of
support in clients and intermediate gateways, as described in
[RFC-3363](https://www.ietf.org/rfc/rfc3363.txt), which moved [RFC-2673](https://www.ietf.org/rfc/2673rfc.txt) to Experimental status; and
[RFC-3364](https://www.ietf.org/rfc/3364rfc.txt), which describes the pros and cons. As such, proposals
that contemplate extended labels SHOULD weigh this deployment cost
against the possibility of implementing functionality in other ways.

Finally, implementations MUST NOT generate or pass Binary Labels in
their communications, as they are now deprecated.



### Message Compression

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



# Resource Records

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


## RR TYPE 1 - A

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

## RR TYPE 2 - NS

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

## RR TYPE 3 - MD (OBSOLETE)

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


## RR TYPE 4 - MF (OBSOLETE)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   MADNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field   | Description |
| -----   | ----------- |
| MADNAME | A \<domain-name\> which specifies a host which has a mail agent for the domain which will accept mail for forwarding to the domain |

MF records cause additional section processing which looks up an A type
record corresponding to MADNAME.

MF is obsolete. See the definition of MX and [RFC-974](https://www.ietf.org/rfc/rfc974.txt) for details of
the new scheme. The recommended policy for dealing with MD RRs found in
a master file is to reject them, or to convert them to MX RRs with a
preference of 10.

## RR TYPE 5 -CNAME

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

## RR TYPE 6 - SOA

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

## RR TYPE 7 - MB (EXPERIMENTAL)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   MADNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field   | Description |
| -----   | ----------- |
| MADNAME | A \<domain-name\> which specifies a host which has the specified mailbox |

MB records cause additional section processing which looks up an A type
RRs corresponding to MADNAME.

## RR TYPE 8 - MG (EXPERIMENTAL)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   MGMNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field   | Description |
| -----   | ----------- |
| MGMNAME | A \<domain-name\> which specifies a mailbox which is a member of the mail group specified by the domain name |

MG records cause no additional section processing.

## RR TYPE 9 - MR (EXPERIMENTAL)

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

## RR TYPE 10 - NULL (EXPERIMENTAL)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                  <anything>                   /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

Anything at all may be in the RDATA field so long as it is 65535 octets
or less.

NULL records cause no additional section processing. NULL RRs are not
allowed in master files. NULLs are used as placeholders in some
experimental extensions of the DNS.

## RR TYPE 11 - WKS

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

## RR TYPE 12 - PTR

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

## RR TYPE 13 - HINFO

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

## RR TYPE 14 - MINFO

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

## RR TYPE 15 - MX

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

## RR TYPE 16 - TXT

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   TXT-DATA                    /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field    | Description |
| -----    | ----------- |
| TXT-DATA | One or more \<character-string\>s |

TXT RRs are used to hold descriptive text. The semantics of the text
depends on the domain where it is found.

## RR TYPE 28 - AAAA

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

## RR TYPE 33 - SRV

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

## RR TYPE 41 - OPT

## OPT Record Definition

### Basic Elements

An OPT pseudo-RR (sometimes called a meta-RR) MAY be added to the
additional data section of a request.

The OPT RR has RR type 41.

If an OPT record is present in a received request, compliant
responders MUST include an OPT record in their respective responses.

An OPT record does not carry any DNS data. It is used only to
contain control information pertaining to the question-and-answer
sequence of a specific transaction. OPT RRs MUST NOT be cached,
forwarded, or stored in or loaded from master files.

The OPT RR MAY be placed anywhere within the additional data section.
When an OPT RR is included within any DNS message, it MUST be the
only OPT RR in that message. If a query message with more than one
OPT RR is received, a FORMERR (RCODE=1) MUST be returned. The
placement flexibility for the OPT RR does not override the need for
the TSIG or SIG(0) RRs to be the last in the additional section
whenever they are present.



### Wire Format

An OPT RR has a fixed part and a variable set of options expressed as
{attribute, value} pairs. The fixed part holds some DNS metadata,
and also a small collection of basic extension elements that we
expect to be so popular that it would be a waste of wire space to
encode them as {attribute, value} pairs.

The fixed part of an OPT RR is structured as follows:

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     NAME                      /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     TYPE                      |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     RDLEN                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field |  Field Type  | Description |
| ----- |  ----------  | ----------- |
| NAME  | domain name  | MUST be 0 (root domain)      |
| TYPE  | u_int16_t    | OPT (41)                     |
| CLASS | u_int16_t    | requestor's UDP payload size |
| TTL   | u_int32_t    | extended RCODE and flags     |
| RDLEN | u_int16_t    | length of all RDATA          |
| RDATA | octet stream | {attribute,value} pairs      |

The variable part of an OPT RR may contain zero or more options in
the RDATA. Each option MUST be treated as a bit field. Each option
is encoded as:

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                 OPTION-CODE                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                 OPTION-LENGTH                 |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                 OPTION-DATA                   /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field | Description |
| ----- | ----------- |
| OPTION-CODE | Assigned by the Expert Review process as defined by the DNSEXT working group and the IESG |
| OPTION-LENGTH | Size (in octets) of OPTION-DATA |
| OPTION-DATA | Varies per OPTION-CODE. MUST be treated as a bit field |

The order of appearance of option tuples is not defined. If one
option modifies the behaviour of another or multiple options are
related to one another in some way, they have the same effect
regardless of ordering in the RDATA wire encoding.

Any OPTION-CODE values not understood by a responder or requestor
MUST be ignored. Specifications of such options might wish to
include some kind of signaled acknowledgement. For example, an
option specification might say that if a responder sees and supports
option XYZ, it MUST include option XYZ in its response.

### OPT Record TTL Field Use

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |     Extended-RCODE    |        Version        |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |DO|                    Z                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field | Description |
| ----- | ----------- |
| Extended-RCODE | Forms the upper 8 bits of extended 12-bit RCODE (together with the 4 bits defined in Section 5.1.1). Note that value 0 indicates that an unextended RCODE is in use (values 0 through 15) |
| Version | Indicates the implementation level of the setter. Full conformance with this specification is indicated by version '0'. Requestors are encouraged to set this to the lowest implemented level capable of expressing a transaction, to minimise the responder and network load of discovering the greatest common implementation level between requestor and responder. A requestor's version numbering strategy MAY ideally be a run-time configuration option. If a responder does not implement the VERSION level of the request, then it MUST respond with RCODE=BADVERS. All responses MUST be limited in format to the VERSION level of the request, but the VERSION of each response SHOULD be the highest implementation level of the responder. In this way, a requestor will learn the implementation level of a responder as a side effect of every response, including error responses and including RCODE=BADVERS |
| DO | DNSSEC OK bit (see Section x.x.x) |
| Z  | Set to zero by senders and ignored by receivers, unless modified in a subsequent specification |

### Behaviour

#### Cache Behaviour

The OPT record MUST NOT be cached.

#### Fallback

If a requestor detects that the remote end does not support EDNS(0),
it MAY issue queries without an OPT record. It MAY cache this
knowledge for a brief time in order to avoid fallback delays in the
future. However, if DNSSEC or any future option using EDNS is
required, no fallback should be performed, as these options are only
signaled through EDNS. If an implementation detects that some
servers for the zone support EDNS(0) while others would force the use
of TCP to fetch all data, preference MAY be given to servers that
support EDNS(0). Implementers SHOULD analyse this choice and the
impact on both endpoints.

#### Requestor's Payload Size

The requestor's UDP payload size (encoded in the RR CLASS field) is
the number of octets of the largest UDP payload that can be
reassembled and delivered in the requestor's network stack.  Note
that path MTU, with or without fragmentation, could be smaller than
this.

Values lower than 512 MUST be treated as equal to 512.

The requestor SHOULD place a value in this field that it can actually
receive.  For example, if a requestor sits behind a firewall that
will block fragmented IP packets, a requestor SHOULD NOT choose a
value that will cause fragmentation.  Doing so will prevent large
responses from being received and can cause fallback to occur.  This
knowledge may be auto-detected by the implementation or provided by a
human administrator.

Note that a 512-octet UDP payload requires a 576-octet IP reassembly
buffer.  Choosing between 1280 and 1410 bytes for IP (v4 or v6) over
Ethernet would be reasonable.

Where fragmentation is not a concern, use of bigger values SHOULD be
considered by implementers.  Implementations SHOULD use their largest
configured or implemented values as a starting point in an EDNS
transaction in the absence of previous knowledge about the
destination server.

Choosing a very large value will guarantee fragmentation at the IP
layer, and may prevent answers from being received due to loss of a
single fragment or to misconfigured firewalls.

The requestor's maximum payload size can change over time.  It MUST
NOT be cached for use beyond the transaction in which it is
advertised.

#### Responder's Payload Size

The responder's maximum payload size can change over time but can
reasonably be expected to remain constant between two closely spaced
sequential transactions, for example, an arbitrary QUERY used as a
probe to discover a responder's maximum UDP payload size, followed
immediately by an UPDATE that takes advantage of this size.  This is
considered preferable to the outright use of TCP for oversized
requests, if there is any reason to suspect that the responder
implements EDNS, and if a request will not fit in the default
512-byte payload size limit.

#### Payload Size Selection

Due to transaction overhead, it is not recommended to advertise an
architectural limit as a maximum UDP payload size.  Even on system
stacks capable of reassembling 64 KB datagrams, memory usage at low
levels in the system will be a concern.  A good compromise may be the
use of an EDNS maximum payload size of 4096 octets as a starting
point.

A requestor MAY choose to implement a fallback to smaller advertised
sizes to work around firewall or other network limitations.  A
requestor SHOULD choose to use a fallback mechanism that begins with
a large size, such as 4096.  If that fails, a fallback around the
range of 1280-1410 bytes SHOULD be tried, as it has a reasonable
chance to fit within a single Ethernet frame.  Failing that, a
requestor MAY choose a 512-byte packet, which with large answers may
cause a TCP retry.

Values of less than 512 bytes MUST be treated as equal to 512 bytes.

#### Support in Middleboxes

In a network that carries DNS traffic, there could be active
equipment other than that participating directly in the DNS
resolution process (stub and caching resolvers, authoritative
servers) that affects the transmission of DNS messages (e.g.,
firewalls, load balancers, proxies, etc.), referred to here as
"middleboxes".

Conformant middleboxes MUST NOT limit DNS messages over UDP to 512
bytes.

Middleboxes that simply forward requests to a recursive resolver MUST
NOT modify and MUST NOT delete the OPT record contents in either
direction.

Middleboxes that have additional functionality, such as answering
queries or acting as intelligent forwarders, SHOULD be able to
process the OPT record and act based on its contents.  These
middleboxes MUST consider the incoming request and any outgoing
requests as separate transactions if the characteristics of the
messages are different.

A more in-depth discussion of this type of equipment and other
considerations regarding their interaction with DNS traffic is found
in [RFC-5625](https://www.ietf.org/rfc/rfc5625.txt).

### Transport Considerations

The presence of an OPT pseudo-RR in a request should be taken as an
indication that the requestor fully implements the given version of
EDNS and can correctly understand any response that conforms to that
feature's specification.

Lack of presence of an OPT record in a request MUST be taken as an
indication that the requestor does not implement any part of this
specification and that the responder MUST NOT include an OPT record
in its response.

Extended agents MUST be prepared for handling interactions with
unextended clients in the face of new protocol elements and fall back
gracefully to unextended DNS when needed.

Responders that choose not to implement the protocol extensions
defined in this document MUST respond with a return code (RCODE) of
FORMERR to messages containing an OPT record in the additional
section and MUST NOT include an OPT record in the response.

If there is a problem with processing the OPT record itself, such as
an option value that is badly formatted or that includes out-of-range
values, a FORMERR MUST be returned.  If this occurs, the response
MUST include an OPT record.  This is intended to allow the requestor
to distinguish between servers that do not implement EDNS and format
errors within EDNS.

The minimal response MUST be the DNS header, question section, and an
OPT record.  This MUST also occur when a truncated response (using
the DNS header's TC bit) is returned.

### Security Considerations

Requestor-side specification of the maximum buffer size may open a
DNS denial-of-service attack if responders can be made to send
messages that are too large for intermediate gateways to forward,
thus leading to potential ICMP storms between gateways and
responders.

Announcing very large UDP buffer sizes may result in dropping of DNS
messages by middleboxes (see Section 6.2.6).  This could cause
retransmissions with no hope of success.  Some devices have been
found to reject fragmented UDP packets.

Announcing UDP buffer sizes that are too small may result in fallback
to TCP with a corresponding load impact on DNS servers.  This is
especially important with DNSSEC, where answers are much larger.

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



# Master Files

Master files are text files that contain RRs in text form. Since the
contents of a zone can be expressed in the form of a list of RRs a
master file is most often used to define a zone, though it can be used
to list a cache's contents. Hence, this section first discusses the
format of RRs in a master file, and then the special considerations when
a master file is used to create a zone in some name server.



## Format

The format of these files is a sequence of entries. Entries are
predominantly line-oriented, though parentheses can be used to continue
a list of items across a line boundary, and text literals can contain
CRLF within the text. Any combination of tabs and spaces act as a
delimiter between the separate items that make up an entry. The end of
any line in the master file can end with a comment. The comment starts
with a ";" (semicolon).

The following entries are defined:

    <blank>[<comment>]

    $ORIGIN <domain-name> [<comment>]

    $INCLUDE <file-name> [<domain-name>] [<comment>]

    <domain-name><rr> [<comment>]

    <blank><rr> [<comment>]

Blank lines, with or without comments, are allowed anywhere in the file.

Two control entries are defined: $ORIGIN and $INCLUDE. $ORIGIN is
followed by a domain name, and resets the current origin for relative
domain names to the stated name. $INCLUDE inserts the named file into
the current file, and may optionally specify a domain name that sets the
relative domain name origin for the included file. $INCLUDE may also
have a comment. Note that a $INCLUDE entry never changes the relative
origin of the parent file, regardless of changes to the relative origin
made within the included file.

The last two forms represent RRs. If an entry for an RR begins with a
blank, then the RR is assumed to be owned by the last stated owner. If
an RR entry begins with a \<domain-name\>, then the owner name is reset.

\<rr\> contents take one of the following forms:

    [<TTL>] [<class>] <type> <RDATA>

    [<class>] [<TTL>] <type> <RDATA>

The RR begins with optional TTL and class fields, followed by a type and
RDATA field appropriate to the type and class. Class and type use the
standard mnemonics, TTL is a decimal integer. Omitted class and TTL
values are default to the last explicitly stated values. Since type and
class mnemonics are disjoint, the parse is unique. (Note that this
order is different from the order used in examples and the order used in
the actual RRs; the given order allows easier parsing and defaulting.)

\<domain-name\>s make up a large share of the data in the master file.
The labels in the domain name are expressed as character strings and
separated by dots. Quoting conventions allow arbitrary characters to be
stored in domain names. Domain names that end in a dot are called
absolute, and are taken as complete. Domain names which do not end in a
dot are called relative; the actual domain name is the concatenation of
the relative part with an origin specified in a $ORIGIN, $INCLUDE, or as
an argument to the master file loading routine. A relative name is an
error when no origin is available.

\<character-string\> is expressed in one or two ways: as a contiguous set
of characters without interior spaces, or as a string beginning with a "
and ending with a ". Inside a " delimited string any character can
occur, except for a " itself, which must be quoted using \\ (back slash).

Because these files are text files several special encodings are
necessary to allow arbitrary data to be loaded. In particular:

| Encoding | Description |
| -------- | ----------- |
|          | Of the root |
|    @     | A free standing @ is used to denote the current origin |
|   \\X     | Where X is any character other than a digit (0-9), is used to quote that character so that its special meaning does not apply. For example, "\\." can be used to place a dot character in a label |
|  \\DDD    | Where each D is a digit is the octet corresponding to the decimal number described by DDD. The resulting octet is assumed to be text and is not checked for special meaning |
|   ( )    | Parentheses are used to group data that crosses a line boundary. In effect, line terminations are not recognized within parentheses |
|    ;     | Semicolon is used to start a comment; the remainder of the line is ignored |



## Use of master files to define zones

When a master file is used to load a zone, the operation should be
suppressed if any errors are encountered in the master file. The
rationale for this is that a single error can have widespread
consequences. For example, suppose that the RRs defining a delegation
have syntax errors; then the server will return authoritative name
errors for all names in the subzone (except in the case where the
subzone is also present on the server).

Several other validity checks that should be performed in addition to
insuring that the file is syntactically correct:

   1. All RRs in the file should have the same class.

   2. Exactly one SOA RR should be present at the top of the zone.

   3. If delegations are present and glue information is required,
      it should be present.

   4. Information present outside of the authoritative nodes in the
      zone should be glue information, rather than the result of an
      origin or similar error.



## Master file example

The following is an example file which might be used to define the
ISI.EDU zone.and is loaded with an origin of ISI.EDU:

    @   IN  SOA     VENERA      Action\.domains (
                                    20     ; SERIAL
                                    7200   ; REFRESH
                                    600    ; RETRY
                                    3600000; EXPIRE
                                    60)    ; MINIMUM

            NS      A.ISI.EDU.
            NS      VENERA
            NS      VAXA
            MX      10      VENERA
            MX      20      VAXA

    A       A       26.3.0.103

    VENERA  A       10.1.0.52
            A       128.9.0.32

    VAXA    A       10.2.0.27
            A       128.9.0.33


    $INCLUDE <SUBSYS>ISI-MAILBOXES.TXT

Where the file \<SUBSYS\>ISI-MAILBOXES.TXT is:

    MOE     MB      A.ISI.EDU.
    LARRY   MB      A.ISI.EDU.
    CURLEY  MB      A.ISI.EDU.
    STOOGES MG      MOE
            MG      LARRY
            MG      CURLEY

Note the use of the \\ character in the SOA RR to specify the responsible
person mailbox "Action.domains@E.ISI.EDU".



# EDNS(`0`)

The Domain Name System's wire protocol includes a number of fixed
fields whose range has been or soon will be exhausted and does not
allow requestors to advertise their capabilities to responders.
In response to this, the backward-compatible Extension Mechanisms for DNS (EDNS(0))
have been created to allow the protocol to grow.



## Introduction

DNS [RFC-1035](https://www.ietf.org/rfc/rfc1035.txt) specifies a message format, and within such messages
there are standard formats for encoding options, errors, and name
compression. The maximum allowable size of a DNS message over UDP
not using EDNS is 512 bytes.
Many of DNS's protocol limits, such as the maximum message size over
UDP, are too small to efficiently support the additional information
that can be conveyed in the DNS (e.g., several IPv6 addresses or DNS
Security (DNSSEC) signatures). Finally, [RFC-1035](https://www.ietf.org/rfc/rfc1035.txt) does not define any
way for implementations to advertise their capabilities to any of the
other actors they interact with.

[RFC-2671](https://www.ietf.org/rfc/rfc2671.txt) added extension mechanisms to DNS. These mechanisms are
widely supported, and a number of new DNS uses and protocol
extensions depend on the presence of these extensions. [RFC-6891](https://www.ietf.org/rfc/rfc6891.txt)
refined and obsoleted [RFC-2671](https://www.ietf.org/rfc/rfc2671.txt).

Unextended agents will not know how to interpret the protocol
extensions. Extended agents need to be prepared for handling the
interactions with unextended clients in the face of new protocol
elements and fall back gracefully to unextended DNS.

EDNS is a hop-by-hop extension to DNS. This means the use of EDNS is
negotiated between each pair of hosts in a DNS resolution process,
for instance, the stub resolver communicating with the recursive
resolver or the recursive resolver communicating with an
authoritative server.

EDNS provides a mechanism to improve the scalability of DNS as its
uses get more diverse on the Internet. It does this by enabling the
use of UDP transport for DNS messages with sizes beyond the 512 limit
specified in [RFC-1035](https://www.ietf.org/rfc/rfc1035.txt) as well as providing extra data space for
additional flags and return codes (RCODEs). However, implementation
experience indicates that adding new RCODEs should be avoided due to
the difficulty in upgrading the installed base. Flags SHOULD be used
only when necessary for DNS resolution to function.

For many uses, an EDNS Option Code may be preferred.

Over time, some applications of DNS have made EDNS a requirement for
their deployment. For instance, DNSSEC uses the additional flag
space introduced in EDNS to signal the request to include DNSSEC data
in a DNS response.

Given the increase in DNS response sizes when including larger data
items such as AAAA records, DNSSEC information (e.g., RRSIG or
DNSKEY), or large TXT records, the additional UDP payload
capabilities provided by EDNS can help improve the scalability of the
DNS by avoiding widespread use of TCP for DNS transport.



## DNS Message Changes



### Message Header

The DNS message header's second full 16-bit word is divided into a
4-bit OPCODE, a 4-bit RCODE, and a number of 1-bit flags (see Section
5.1). Some of these flag values were marked for
future use, and most of these have since been allocated. Also, most
of the RCODE values are now in use. The OPT pseudo-RR specified
below contains extensions to the RCODE bit field as well as
additional flag bits.

### UDP Message Size

Traditional DNS messages are limited to 512 octets in size when sent
over UDP (see Section 2.3). Fitting the increasing amounts of data that can
be transported in DNS in this 512-byte limit is becoming more
difficult. For instance, inclusion of DNSSEC records frequently
requires a much larger response than a 512-byte message can hold.

EDNS(0) specifies a way to advertise additional features such as
larger response size capability, which is intended to help avoid
truncated UDP responses, which in turn cause retry over TCP. It
therefore provides support for transporting these larger packet sizes
without needing to resort to TCP for transport.

### The OPT Psuedo-RR

The main change in EDNS(`0`) is the addition of the OPT "psuedo"-RR. This addition is
detailed in Section x.x.x.

# DNSSEC

It's a whopper.
