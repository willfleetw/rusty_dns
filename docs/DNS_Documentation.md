% Domain Name System (DNS)
% William Fleetwood

>**TODO**
>
>* Update to include DNSSEC
>* Update resolver and name server algs to take into account DNSSEC
>* Update section references
>* Update resource records section of document (missing RRs)
>* Fillout Glossary with terms and references to document and RFCs
>* Update RCODE section to include extended values, and clearer description of extened RCODE meaning form EDNS
>* Find new ToC formatting options
>* I DEMAND MOAR ASCII ART!
>* Include Zone Transfer protocol sections

# Introduction

This document describes the Domain Name System (DNS), including the design, server roles, algorithms, data, use cases, and on the wire message protocol that make up the DNS.
The DNS design and usage is defined in a large number of different RFCs starting back in 1983, many of which have been corrected, clarified, extended, updated, or made completely obsolete by more modern RFCs. This makes understanding the current DNS specifications in its entirety quite difficult and realistically impossible for most people.

In order to combat this issue, and thus make any future DNS development both easier and more accurate, this document attempts to compile all the relevent DNS RFCs into one single, up to date, clear, all encompassing document. Note that in the future, depending on the size of this document, it may be split up into multiple documents for readability.

For a *fairly* complete list of DNS related RFCs, see <https://www.bind9.net/rfc>.

Compiled RFCs:

* [RFC-1033](https://www.ietf.org/rfc/rfc1033.txt)
* [RFC-1034](https://www.ietf.org/rfc/rfc1034.txt)
* [RFC-1035](https://www.ietf.org/rfc/rfc1035.txt)
* [RFC-2181](https://www.ietf.org/rfc/rfc2181.txt)
* [RFC-2308](https://www.ietf.org/rfc/rfc2308.txt)
* (*TODO*) [RFC-2535](https://ietf.org/rfc/rfc2535.txt)
* (*TODO*) [RFC-2672](https://ietf.org/rfc/rfc2672.txt)
* (*TODO*) [RFC-2931](https://ietf.org/rfc/rfc2931.txt)
* [RFC-3425](https://www.ietf.org/rfc/rfc3425.txt)
* [RFC-4033](https://www.ietf.org/rfc/rfc4033.txt)
* [RFC-4034](https://www.ietf.org/rfc/rfc4034.txt)
* (*TODO*) [RFC-4035](https://www.ietf.org/rfc/rfc4035.txt)
* [RFC-6891](https://www.ietf.org/rfc/rfc6891.txt)

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

## Name Syntax

The DNS itself places only one restriction on the particular labels
that can be used to identify resource records. That one restriction
relates to the length of the label and the full name. The length of
any one label is limited to between 1 and 63 octets. A full domain
name is limited to 255 octets (including the separators). The zero
length full name is defined as representing the root of the DNS tree,
and is typically written and displayed as ".". Those restrictions
aside, any binary string whatever can be used as the label of any
resource record. Similarly, any binary string can serve as the value
of any record that includes a domain name as some or all of its value
(SOA, NS, MX, PTR, CNAME, and any others that may be added).
Implementations of the DNS protocols must not place any restrictions
on the labels that can be used. In particular, DNS servers must not
refuse to serve a zone because it contains labels that might not be
acceptable to some DNS client programs. A DNS server may be
configurable to issue warnings when loading, or even to refuse to
load, a primary zone containing labels that might be considered
questionable, however this should not happen by default.

Note however, that the various applications that make use of DNS data
can have restrictions imposed on what particular values are
acceptable in their environment. For example, that any binary label
can have an MX record does not imply that any binary name can be used
as the host part of an e-mail address. Clients of the DNS can impose
whatever restrictions are appropriate to their circumstances on the
values they use as keys for DNS lookup requests, and on the values
returned by the DNS. If the client has such restrictions, it is
solely responsible for validating the data from the DNS to ensure
that it conforms before it makes any use of that data.

## Size Limits

Various objects and parameters in the DNS have size limits. They are
listed below. Some could be easily changed, others are more
fundamental.

| Parameter | Limit |
| --------- | ----- |
|  labels   | 63 octets or less |
|  domain names    | 255 octets or less (including separators) |
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

The specific format of the DNS message format is described later in [DNS Packet Structure].


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
of connected nodes forms a "zone". The zone is authoritative for all names
in the connected region. Note that the "cuts" in the namespace tree may be
different for different classes.

The name of the node closest to the root node is often used to identify
the zone itself.

Generally, these cuts are made at points where different orginizations are
willing to take ownership of a subtree, or where an orginization wants to
make further internal partitions.

### Zone Cuts

Each zone cut separates a "child" zone (below the cut) from a "parent" zone
(above the cut). The domain name that appears at the top of a zone (just below the cut
that separates the zone from its parent) is called the zone's
"origin". The name of the zone is the same as the name of the domain
at the zone's origin. Each zone comprises that subset of the DNS
tree that is at or below the zone's origin, and that is above the
cuts that separate the zone from its children (if any). The
existence of a zone cut is indicated in the parent zone by the
existence of NS records (and potentially NSEC, DS, and RRSIG records) specifying the origin of the child zone. A
child zone does not contain any explicit reference to its parent.

#### Zone Authority

The authoritative servers for a zone are enumerated in the NS records
for the origin of the zone, which, along with a Start of Authority
(SOA) record are the mandatory records in every zone. Such a server
is authoritative for all resource records in a zone that are not in
another zone. The NS records that indicate a zone cut are the
property of the child zone created, as are any other records for the
origin of that child zone, or any sub-domains of it. A server for a
zone should not return authoritative answers for queries related to
names in another zone, which includes the NS, and perhaps A, records
at a zone cut, unless it also happens to be a server for the other
zone.

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

### Server Reply Source Address and Port Number Selection

Most, if not all, DNS clients and name servers expect the address from which a
reply is received to be the same addres as that to which the query
eliciting the reply was sent. The address, along with the identifier (ID) in
the reply is used for disambiguating replies, and filtering spurious responses.
This may, or may not, have been intended when the DNS was designed, but is now
a fact of life.

If a multi-homed host running a DNS server generates replies using a source
address that is not the same as the destination adress from the client's request
packet, the reply would be discarded by the client due to being seen as a spurious
response. Because of this, DNS responses over UDP MUST use the same IP address as
the destination IP specified in the original UDP query.

Replies should also always be sent from the port to which they were directed.
Replies should also use the source port of the question as the destination port
of the response.

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
does not exist in the DNS. The first parts of this section deal
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
    |QR|   OPCODE  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
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
| AD      | Authentic Data - The response has been authenticated. See [x.x.x] |
| CD      | Checking Disabled - Disables DNSSEC validation for the query. See [x.x.x] |
| RCODE   | Response code - this 4 bit field is set as part of responses to denote result. |
| QDCOUNT | An unsigned 16 bit integer specifying the number of entries in the question section |
| ANCOUNT | An unsigned 16 bit integer specifying the number of resource records in the answer section |
| NSCOUNT | An unsigned 16 bit integer specifying the number of name server resource records in the authority records section |
| ARCOUNT | An unsigned 16 bit integer specifying the number of resource records in the additional records section |

### The TC (truncated) header bit

The TC bit should be set in responses only when an RRSet is required
as a part of the response, but could not be included in its entirety.
The TC bit should not be set merely because some extra information
could have been included, but there was insufficient room. This
includes the results of additional section processing. In such cases
the entire RRSet that will not fit in the response should be omitted,
and the reply sent as is, with the TC bit clear. If the recipient of
the reply needs the omitted data, it can construct a query for that
data and send that separately.

Where TC is set, the partial RRSet that would not completely fit may
be left in the response. When a DNS client receives a reply with TC
set, it should ignore that response, and query again, using a
mechanism, such as a TCP connection, that will permit larger replies.

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

### Time to Live (TTL)

The definition of values appropriate to the TTL field in STD 13 is
not as clear as it could be, with respect to how many significant
bits exist, and whether the value is signed or unsigned. It is
hereby specified that a TTL value is an unsigned number, with a
minimum value of 0, and a maximum value of 2147483647. That is, a
maximum of 2^31 - 1. When transmitted, this value shall be encoded
in the less significant 31 bits of the 32 bit TTL field, with the
most significant, or sign, bit set to zero.

Implementations should treat TTL values received with the most
significant bit set as if the entire value received was zero.

Implementations are always free to place an upper bound on any TTL
received, and treat any larger values as if they were that upper
bound. The TTL specifies a maximum time to live, not a mandatory
time to live.

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
packet (see [Message Compression]).



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

The RDATA format described here is the same RDATA part of DNS message packets as
described in [Resource Record Format].

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

Note that the \<domain-name\> in NSDNAME must NEVER be an alias for a CNAME.

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

## RR TYPE 5 - CNAME

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     CNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field | Description |
| ----- | ----------- |
| CNAME | A \<domain-name\> which specifies the canonical or primary name for the owner. The owner name is an alias |

CNAME RRs cause no additional section processing, but name servers may
choose to restart the query at the canonical name in certain cases. See
the description of name server logic in [Name Server Algorithm] for details.

The CNAME record exists to provide the
canonical name associated with an alias name. There may be only one
such canonical name for any one alias. That name should generally be
a name that exists elsewhere in the DNS, though there are some rare
applications for aliases with the accompanying canonical name
undefined in the DNS. An alias name (label of a CNAME record) may,
if DNSSEC is in use, have RRSIG, NSEC, and DNSKEY RRs, but may have no
other data. That is, for any label in the DNS (any domain name)
exactly one of the following is true:

* one CNAME record exists, optionally accompanied by RRSIG, NSEC, and DNSKEY RRs,
* one or more records exist, none being CNAME records,
* the name exists, but has no associated RRs of any type,
* the name does not exist at all.

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

| Field | Description |
| ----- | ----------- |
| MNAME   | The \<domain-name\> of the name server that is the primary (master) name server for this zone |
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

### Placement of SOA RRs in an Authoritative Answer

[RFC-1034](https://www.ietf.org/rfc/rfc1034.txt), in section 3.7, indicates that the authority section of an
authoritative answer may contain the SOA record for the zone from
which the answer was obtained. When discussing negative caching,
[RFC-1034](https://www.ietf.org/rfc/rfc1034.txt) section 4.3.4 refers to this technique but mentions the
additional section of the response. The former is correct, as is
implied by the example shown in section 6.2.5 of [RFC-1034](https://www.ietf.org/rfc/rfc1034.txt). SOA
records, if added, are to be placed in the authority section.

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

Confusion about canonical names has lead to a belief that a PTR
record should have exactly one RR in its RRSet. This is incorrect,
the relevant section of [RFC-1034](https://www.ietf.org/rfc/rfc1034.txt) (section 3.6.2) indicates that the
value of a PTR record should be a canonical name. That is, it should
not be an alias. There is no implication in that section that only
one PTR record is permitted for a name. No such restriction should
be inferred.

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

Note that the \<domain-name\> in EXCHANGE must NEVER be an alias for a CNAME.

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

The OPT RR was added as a part of [EDNS(`0`)]. It is a resource record meant to aid
in the communication of additional information and advertisement of a servers capabilities
to other actors in the DNS protocol. An OPT RR is not a part of the data stored in the DNS, and is
not attached to any domain name or zone. It is something generated on the fly by a DNS client or server.

### OPT Record Definition

#### Basic Elements

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
the TSIG or SIG(`0`) RRs to be the last in the additional section
whenever they are present.



#### Wire Format

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

#### OPT Record TTL Field Use

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |     Extended-RCODE    |        Version        |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |DO|                    Z                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

| Field | Description |
| ----- | ----------- |
| Extended-RCODE | Forms the upper 8 bits of extended 12-bit RCODE (together with the 4 bits defined in [Header Format]). Note that value 0 indicates that an unextended RCODE is in use (values 0 through 15) |
| Version | Indicates the implementation level of the setter. Full conformance with this specification is indicated by version '0'. Requestors are encouraged to set this to the lowest implemented level capable of expressing a transaction, to minimise the responder and network load of discovering the greatest common implementation level between requestor and responder. A requestor's version numbering strategy MAY ideally be a run-time configuration option. If a responder does not implement the VERSION level of the request, then it MUST respond with RCODE=BADVERS. All responses MUST be limited in format to the VERSION level of the request, but the VERSION of each response SHOULD be the highest implementation level of the responder. In this way, a requestor will learn the implementation level of a responder as a side effect of every response, including error responses and including RCODE=BADVERS |
| DO | DNSSEC OK bit (see [x.x.x]) |
| Z  | Set to zero by senders and ignored by receivers, unless modified in a subsequent specification |

#### Behaviour

##### Cache Behaviour

The OPT record MUST NOT be cached.

##### Fallback

If a requestor detects that the remote end does not support EDNS(`0`),
it MAY issue queries without an OPT record. It MAY cache this
knowledge for a brief time in order to avoid fallback delays in the
future. However, if DNSSEC or any future option using EDNS is
required, no fallback should be performed, as these options are only
signaled through EDNS. If an implementation detects that some
servers for the zone support EDNS(`0`) while others would force the use
of TCP to fetch all data, preference MAY be given to servers that
support EDNS(`0`). Implementers SHOULD analyse this choice and the
impact on both endpoints.

##### Requestor's Payload Size

The requestor's UDP payload size (encoded in the RR CLASS field) is
the number of octets of the largest UDP payload that can be
reassembled and delivered in the requestor's network stack. Note
that path MTU, with or without fragmentation, could be smaller than
this.

Values lower than 512 MUST be treated as equal to 512.

The requestor SHOULD place a value in this field that it can actually
receive. For example, if a requestor sits behind a firewall that
will block fragmented IP packets, a requestor SHOULD NOT choose a
value that will cause fragmentation. Doing so will prevent large
responses from being received and can cause fallback to occur. This
knowledge may be auto-detected by the implementation or provided by a
human administrator.

Note that a 512-octet UDP payload requires a 576-octet IP reassembly
buffer. Choosing between 1280 and 1410 bytes for IP (v4 or v6) over
Ethernet would be reasonable.

Where fragmentation is not a concern, use of bigger values SHOULD be
considered by implementers. Implementations SHOULD use their largest
configured or implemented values as a starting point in an EDNS
transaction in the absence of previous knowledge about the
destination server.

Choosing a very large value will guarantee fragmentation at the IP
layer, and may prevent answers from being received due to loss of a
single fragment or to misconfigured firewalls.

The requestor's maximum payload size can change over time. It MUST
NOT be cached for use beyond the transaction in which it is
advertised.

##### Responder's Payload Size

The responder's maximum payload size can change over time but can
reasonably be expected to remain constant between two closely spaced
sequential transactions, for example, an arbitrary QUERY used as a
probe to discover a responder's maximum UDP payload size, followed
immediately by an UPDATE that takes advantage of this size. This is
considered preferable to the outright use of TCP for oversized
requests, if there is any reason to suspect that the responder
implements EDNS, and if a request will not fit in the default
512-byte payload size limit.

##### Payload Size Selection

Due to transaction overhead, it is not recommended to advertise an
architectural limit as a maximum UDP payload size. Even on system
stacks capable of reassembling 64 KB datagrams, memory usage at low
levels in the system will be a concern. A good compromise may be the
use of an EDNS maximum payload size of 4096 octets as a starting
point.

A requestor MAY choose to implement a fallback to smaller advertised
sizes to work around firewall or other network limitations. A
requestor SHOULD choose to use a fallback mechanism that begins with
a large size, such as 4096. If that fails, a fallback around the
range of 1280-1410 bytes SHOULD be tried, as it has a reasonable
chance to fit within a single Ethernet frame. Failing that, a
requestor MAY choose a 512-byte packet, which with large answers may
cause a TCP retry.

Values of less than 512 bytes MUST be treated as equal to 512 bytes.

##### Support in Middleboxes

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
process the OPT record and act based on its contents. These
middleboxes MUST consider the incoming request and any outgoing
requests as separate transactions if the characteristics of the
messages are different.

A more in-depth discussion of this type of equipment and other
considerations regarding their interaction with DNS traffic is found
in [RFC-5625](https://www.ietf.org/rfc/rfc5625.txt).

#### Transport Considerations

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
values, a FORMERR MUST be returned. If this occurs, the response
MUST include an OPT record. This is intended to allow the requestor
to distinguish between servers that do not implement EDNS and format
errors within EDNS.

The minimal response MUST be the DNS header, question section, and an
OPT record. This MUST also occur when a truncated response (using
the DNS header's TC bit) is returned.

#### Security Considerations

Requestor-side specification of the maximum buffer size may open a
DNS denial-of-service attack if responders can be made to send
messages that are too large for intermediate gateways to forward,
thus leading to potential ICMP storms between gateways and
responders.

Announcing very large UDP buffer sizes may result in dropping of DNS
messages by middleboxes (see [Support in Middleboxes]). This could cause
retransmissions with no hope of success. Some devices have been
found to reject fragmented UDP packets.

Announcing UDP buffer sizes that are too small may result in fallback
to TCP with a corresponding load impact on DNS servers. This is
especially important with DNSSEC, where answers are much larger.


## RR TYPE 43 - DS

      0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    Key Tag                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |        Algorithm      |     Digest Type       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     Digest                    /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

The DS Resource Record refers to a DNSKEY RR and is used in the DNS
DNSKEY authentication process. A DS RR refers to a DNSKEY RR by
storing the key tag, algorithm number, and a digest of the DNSKEY RR.
Note that while the digest should be sufficient to identify the
public key, storing the key tag and key algorithm helps make the
identification process more efficient. By authenticating the DS
record, a resolver can authenticate the DNSKEY RR to which the DS
record points. The key authentication process is described in
[x.x.x].

The DS RR and its corresponding DNSKEY RR have the same owner name,
but they are stored in different locations. The DS RR appears only
on the upper (parental) side of a delegation, and is authoritative
data in the parent zone. For example, the DS RR for "example.com" is
stored in the "com" zone (the parent zone) rather than in the
"example.com" zone (the child zone). The corresponding DNSKEY RR is
stored in the "example.com" zone (the child zone). This simplifies
DNS zone management and zone signing but introduces special response
processing requirements for the DS RR; these are described in
[x.x.x].

The type number for the DS record is 43.

The DS resource record is class independent.

The DS RR has no special TTL requirements.

### The Key Tag Field

The Key Tag field lists the key tag of the DNSKEY RR referred to by
the DS record, in network byte order.

The Key Tag used by the DS RR is identical to the Key Tag used by
RRSIG RRs. Appendix B describes how to compute a Key Tag.

### The Algorithm Field

The Algorithm field lists the algorithm number of the DNSKEY RR
referred to by the DS record.

The algorithm number used by the DS RR is identical to the algorithm
number used by RRSIG and DNSKEY RRs. [x.x.x] lists the
algorithm number types.

### The Digest Type Field

The DS RR refers to a DNSKEY RR by including a digest of that DNSKEY
RR. The Digest Type field identifies the algorithm used to construct
the digest. [x.x.x] lists the possible digest algorithm types.

### The Digest Field

The DS record refers to a DNSKEY RR by including a digest of that
DNSKEY RR.

The digest is calculated by concatenating the canonical form of the
fully qualified owner name of the DNSKEY RR with the DNSKEY RDATA,
and then applying the digest algorithm.

    digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);

    "|" denotes concatenation

    DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.

The size of the digest may vary depending on the digest algorithm and
DNSKEY RR size. As of the time of this writing, the only defined
digest algorithm is SHA-1, which produces a 20 octet digest.

### Processing of DS RRs When Validating Responses

The DS RR links the authentication chain across zone boundaries, so
the DS RR requires extra care in processing. The DNSKEY RR referred
to in the DS RR MUST be a DNSSEC zone key. The DNSKEY RR Flags MUST
have Flags bit 7 set. If the DNSKEY flags do not indicate a DNSSEC
zone key, the DS RR (and the DNSKEY RR it references) MUST NOT be
used in the validation process.

### The DS RR Presentation Format

The presentation format of the RDATA portion is as follows:

The Key Tag field MUST be represented as an unsigned decimal integer.

The Algorithm field MUST be represented either as an unsigned decimal
integer or as an algorithm mnemonic specified in Appendix A.1.

The Digest Type field MUST be represented as an unsigned decimal
integer.

The Digest MUST be represented as a sequence of case-insensitive
hexadecimal digits. Whitespace is allowed within the hexadecimal
text.

The following example shows a DNSKEY RR and its corresponding DS RR.

   dskey.example.com. 86400 IN DNSKEY 256 3 5 ( AQOeiiR0GOMYkDshWoSKz9Xz
                                             fwJr1AYtsmx3TGkJaNXVbfi/
                                             2pHm822aJ5iI9BMzNXxeYCmZ
                                             DRD99WYwYqUSdjMmmAphXdvx
                                             egXd/M5+X7OrzKBaMbCVdFLU
                                             Uh6DhweJBjEVv5f2wwjM9Xzc
                                             nOf+EPbtG9DMBmADjFDc2w/r
                                             ljwvFw==
                                             ) ;  key id = 60485

   dskey.example.com. 86400 IN DS 60485 5 1 ( 2BB183AF5F22588179A53B0A
                                              98631FAD1A292118 )

The first four text fields specify the name, TTL, Class, and RR type
(DS). Value 60485 is the key tag for the corresponding
"dskey.example.com." DNSKEY RR, and value 5 denotes the algorithm
used by this "dskey.example.com." DNSKEY RR. The value 1 is the
algorithm used to construct the digest, and the rest of the RDATA
text is the digest in hexadecimal.

## RR TYPE 46 - RRSIG

DNSSEC uses public key cryptography to sign and authenticate DNS
resource record sets (RRsets). Digital signatures are stored in
RRSIG resource records and are used in the DNSSEC authentication
process described in [x.x.x]. A validator can use these RRSIG RRs
to authenticate RRsets from the zone. The RRSIG RR MUST only be used
to carry verification material (digital signatures) used to secure
DNS operations.

An RRSIG record contains the signature for an RRset with a particular
name, class, and type. The RRSIG RR specifies a validity interval
for the signature and uses the Algorithm, the Signer's Name, and the
Key Tag to identify the DNSKEY RR containing the public key that a
validator can use to verify the signature.

Because every authoritative RRset in a zone must be protected by a
digital signature, RRSIG RRs must be present for names containing a
CNAME RR. A RRSIG and NSEC (see [x.x.x])
MUST exist for the same name as a CNAME resource record in a signed
zone.

The Type value for the RRSIG RR type is 46.

The RRSIG RR is class independent.

An RRSIG RR MUST have the same class as the RRset it covers.

The TTL value of an RRSIG RR MUST match the TTL value of the RRset it
covers. This is an exception to the rules for TTL values
of individual RRs within a RRset (see [TTLs of RRs in an RRSet]): individual RRSIG RRs with the same
owner name will have different TTL values if the RRsets they cover
have different TTL values.

      0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                 Type Covered                  |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |       Algorithm       |        Labels         |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                Original TTL                   |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |            Signature Expiration               |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |            Signature Inception                |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    Key Tag                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /               Signer's Name                   /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                  Signature                    /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

### The Type Covered Field

The Type Covered field identifies the type of the RRSet that is covered by this RRSIG record.

### The Algorithm Field

The Algorithm field identifies the cryptographic algorithm used to create
the signature. A list of DNSSEC algorithm types can be found in [x.x.x].

### The Labels Field

The Labels field specifies the number of labels in the original RRSIG
RR owner name. The significance of this field is that a validator
uses it to determine whether the answer was synthesized from a
wildcard. If so, it can be used to determine what owner name was
used in generating the signature.

To validate a signature, the validator needs the original owner name
that was used to create the signature. If the original owner name
contains a wildcard label ("*"), the owner name may have been
expanded by the server during the response process, in which case the
validator will have to reconstruct the original owner name in order
to validate the signature. [x.x.x] describes how to use the Labels
field to reconstruct the original owner name.

The value of the Labels field MUST NOT count either the null (root)
label that terminates the owner name or the wildcard label (if
present). The value of the Labels field MUST be less than or equal
to the number of labels in the RRSIG owner name. For example,
"www.example.com." has a Labels field value of 3, and
"*.example.com." has a Labels field value of 2. Root (".") has a
Labels field value of 0.

Although the wildcard label is not included in the count stored in
the Labels field of the RRSIG RR, the wildcard label is part of the
RRset's owner name when the signature is generated or verified.

### The Original TTL Field

The Original TTL field specifies the TTL of the covered RRset as it
appears in the authoritative zone.

The Original TTL field is necessary because a caching resolver
decrements the TTL value of a cached RRset. In order to validate a
signature, a validator requires the original TTL. [x.x.x]
describes how to use the Original TTL field value to reconstruct the
original TTL.

### The Signature Expiration and Inception Fields

The Signature Expiration and Inception fields specify a validity
period for the signature. The RRSIG record MUST NOT be used for
authentication prior to the inception date and MUST NOT be used for
authentication after the expiration date.

The Signature Expiration and Inception field values specify a date
and time in the form of a 32-bit unsigned number of seconds elapsed
since `1 January 1970 00:00:00 UTC`, ignoring leap seconds, in network
byte order. The longest interval that can be expressed by this
format without wrapping is approximately 136 years. An RRSIG RR can
have an Expiration field value that is numerically smaller than the
Inception field value if the expiration field value is near the
32-bit wrap-around point or if the signature is long lived. Because
of this, all comparisons involving these fields MUST use "Serial
number arithmetic", as defined in [RFC-1982](https://ietf.org/rfc/rfc1982.txt). As a direct
consequence, the values contained in these fields cannot refer to
dates more than 68 years in either the past or the future.

### The Key Tag Field

The Key Tag field contains the key tag value of the DNSKEY RR that
validates this signature, in network byte order. [x.x.x] explains
how to calculate Key Tag values.

### The Signer's Name Field

The Signer's Name field value identifies the owner name of the DNSKEY
RR that a validator is supposed to use to validate this signature.
The Signer's Name field MUST contain the name of the zone of the
covered RRset. A sender MUST NOT use DNS name compression on the
Signer's Name field when transmitting a RRSIG RR.

### The Signature Field

The Signature field contains the cryptographic signature that covers
the RRSIG RDATA (excluding the Signature field) and the RRset
specified by the RRSIG owner name, RRSIG class, and RRSIG Type
Covered field. The format of this field depends on the algorithm in
use, and these formats are described in separate companion documents.

#### Signature Calculation

A signature covers the RRSIG RDATA (excluding the Signature Field)
and covers the data RRset specified by the RRSIG owner name, RRSIG
class, and RRSIG Type Covered fields. The RRset is in canonical form
(see [x.x.x]), and the set RR(1),...RR(n) is signed as follows:

        signature = sign(RRSIG_RDATA | RR(1) | RR(2)... ) where

        "|" denotes concatenation;

        RRSIG_RDATA is the wire format of the RRSIG RDATA fields
            with the Signer's Name field in canonical form and
            the Signature field excluded;

        RR(i) = owner | type | class | TTL | RDATA length | RDATA

            "owner" is the fully qualified owner name of the RRset in
            canonical form (for RRs with wildcard owner names, the
            wildcard label is included in the owner name);

            Each RR MUST have the same owner name as the RRSIG RR;

            Each RR MUST have the same class as the RRSIG RR;

            Each RR in the RRset MUST have the RR type listed in the
            RRSIG RR's Type Covered field;

            Each RR in the RRset MUST have the TTL listed in the
            RRSIG Original TTL Field;

            Any DNS names in the RDATA field of each RR MUST be in
            canonical form; and

            The RRset MUST be sorted in canonical order.

See [x.x.x] and [x.x.x] for details on canonical form and ordering
of RRsets.

### The RRSIG RR Presentation Format

The presentation format of the RDATA portion is as follows:

The Type Covered field is represented as an RR type mnemonic. When
the mnemonic is not known, the TYPE representation as described in
[RFC 3597], Section 5, MUST be used.

The Algorithm field value MUST be represented either as an unsigned
decimal integer or as an algorithm mnemonic, as specified in Appendix
A.1.

The Labels field value MUST be represented as an unsigned decimal
integer.

The Original TTL field value MUST be represented as an unsigned
decimal integer.

The Signature Expiration Time and Inception Time field values MUST be
represented either as an unsigned decimal integer indicating seconds
since `1 January 1970 00:00:00 UTC`, or in the form YYYYMMDDHHmmSS in
UTC, where:

    YYYY is the year (0001-9999, but see Section 3.1.5);
    MM is the month number (01-12);
    DD is the day of the month (01-31);
    HH is the hour, in 24 hour notation (00-23);
    mm is the minute (00-59); and
    SS is the second (00-59).

Note that it is always possible to distinguish between these two
formats because the YYYYMMDDHHmmSS format will always be exactly 14
digits, while the decimal representation of a 32-bit unsigned integer
can never be longer than 10 digits.

The Key Tag field MUST be represented as an unsigned decimal integer.

The Signer's Name field value MUST be represented as a domain name.

The Signature field is represented as a Base64 encoding of the
signature. Whitespace is allowed within the Base64 text. See
[The DNSKEY RR Presentation Format]

The following RRSIG RR stores the signature for the A RRset of
host.example.com:

    host.example.com. 86400 IN RRSIG A 5 3 86400 20030322173103 (
                                    20030220173103 2642 example.com.
                                    oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTr
                                    PYGv07h108dUKGMeDPKijVCHX3DDKdfb+v6o
                                    B9wfuh3DTJXUAfI/M0zmO/zz8bW0Rznl8O3t
                                    GNazPwQKkRN20XPXV6nwwfoXmJQbsLNrLfkG
                                    J5D6fwFm8nN+6pBzeDQfsS3Ap3o= )

The first four fields specify the owner name, TTL, Class, and RR type
(RRSIG). The "A" represents the Type Covered field. The value 5
identifies the algorithm used (RSA/SHA1) to create the signature.
The value 3 is the number of Labels in the original owner name. The
value 86400 in the RRSIG RDATA is the Original TTL for the covered A
RRset. 20030322173103 and 20030220173103 are the expiration and
inception dates, respectively. 2642 is the Key Tag, and example.com.
is the Signer's Name. The remaining text is a Base64 encoding of the
signature.

Note that combination of RRSIG RR owner name, class, and Type Covered
indicates that this RRSIG covers the "host.example.com" A RRset. The
Label value of 3 indicates that no wildcard expansion was used. The
Algorithm, Signer's Name, and Key Tag indicate that this signature
can be authenticated using an example.com zone DNSKEY RR whose
algorithm is 5 and whose key tag is 2642

## RR TYPE 47 - NSEC

      0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /               Next Domain Name                /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                Type Bit Maps                  /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

The NSEC resource record lists two separate things: the next owner
name (in the canonical ordering of the zone) that contains
authoritative data or a delegation point NS RRset, and the set of RR
types present at the NSEC RR's owner name. The complete
set of NSEC RRs in a zone indicates which authoritative RRsets exist
in a zone and also form a chain of authoritative owner names in the
zone. This information is used to provide authenticated denial of
existence for DNS data, as described in [x.x.x].

Because every authoritative name in a zone must be part of the NSEC
chain, NSEC RRs must be present for names containing a CNAME RR.
This is a change to the traditional DNS specification [RFC-1034](https://ietf.org/rfc/rfc1034.txt),
which stated that if a CNAME is present for a name, it is the only
type allowed at that name. An RRSIG (see Section 3) and NSEC MUST
exist for the same name as does a CNAME resource record in a signed
zone.

See [x.x.x] for discussion of how a zone signer determines
precisely which NSEC RRs it has to include in a zone.

The type value for the NSEC RR is 47.

The NSEC RR is class independent.

The NSEC RR SHOULD have the same TTL value as the SOA minimum TTL
field. This is in the spirit of negative caching (see [Negative Response Caching]).

### The Next Domain Name Field

The Next Domain field contains the next owner name (in the canonical
ordering of the zone) that has authoritative data or contains a
delegation point NS RRset; see [x.x.x] for an explanation of
canonical ordering. The value of the Next Domain Name field in the
last NSEC record in the zone is the name of the zone apex (the owner
name of the zone's SOA RR). This indicates that the owner name of
the NSEC RR is the last name in the canonical ordering of the zone.

A sender MUST NOT use DNS name compression on the Next Domain Name
field when transmitting an NSEC RR.

Owner names of RRsets for which the given zone is not authoritative
(such as glue records) MUST NOT be listed in the Next Domain Name
unless at least one authoritative RRset exists at the same owner
name.

### The Type Bit Maps Field

The Type Bit Maps field identifies the RRset types that exist at the
NSEC RR's owner name.

The RR type space is split into 256 window blocks, each representing
the low-order 8 bits of the 16-bit RR type space. Each block that
has at least one active RR type is encoded using a single octet
window number (from 0 to 255), a single octet bitmap length (from 1
to 32) indicating the number of octets used for the window block's
bitmap, and up to 32 octets (256 bits) of bitmap.

Blocks are present in the NSEC RR RDATA in increasing numerical
order.

    Type Bit Maps Field = ( Window Block # | Bitmap Length | Bitmap )+

    where "|" denotes concatenation.

Each bitmap encodes the low-order 8 bits of RR types within the
window block, in network bit order. The first bit is bit 0. For
window block 0, bit 1 corresponds to RR type 1 (A), bit 2 corresponds
to RR type 2 (NS), and so forth. For window block 1, bit 1
corresponds to RR type 257, and bit 2 to RR type 258. If a bit is
set, it indicates that an RRset of that type is present for the NSEC
RR's owner name. If a bit is clear, it indicates that no RRset of
that type is present for the NSEC RR's owner name.

Bits representing pseudo-types MUST be clear, as they do not appear
in zone data. If encountered, they MUST be ignored upon being read.

Blocks with no types present MUST NOT be included. Trailing zero
octets in the bitmap MUST be omitted. The length of each block's
bitmap is determined by the type code with the largest numerical
value, within that block, among the set of RR types present at the
NSEC RR's owner name. Trailing zero octets not specified MUST be
interpreted as zero octets.

The bitmap for the NSEC RR at a delegation point requires special
attention. Bits corresponding to the delegation NS RRset and the RR
types for which the parent zone has authoritative data MUST be set;
bits corresponding to any non-NS RRset for which the parent is not
authoritative MUST be clear.

A zone MUST NOT include an NSEC RR for any domain name that only
holds glue records.

### Inclusion of Wildcard Names in NSEC RDATA

If a wildcard owner name appears in a zone, the wildcard label ("*")
is treated as a literal symbol and is treated the same as any other
owner name for the purposes of generating NSEC RRs. Wildcard owner
names appear in the Next Domain Name field without any wildcard
expansion. [x.x.x] describes the impact of wildcards on
authenticated denial of existence.

### The NSEC RR Presentation Format

The presentation format of the RDATA portion is as follows:

The Next Domain Name field is represented as a domain name.

The Type Bit Maps field is represented as a sequence of RR type
mnemonics. When the mnemonic is not known, the TYPE representation
described in [RFC-3597](https://ietf.org/rfc/rfc3579.txt), Section 5, MUST be used.

The following NSEC RR identifies the RRsets associated with
alfa.example.com. and identifies the next authoritative name after
alfa.example.com.

    alfa.example.com. 86400 IN NSEC host.example.com. (
                                    A MX RRSIG NSEC TYPE1234 )

The first four text fields specify the name, TTL, Class, and RR type
(NSEC). The entry host.example.com. is the next authoritative name
after alfa.example.com. in canonical order. The A, MX, RRSIG, NSEC,
and TYPE1234 mnemonics indicate that there are A, MX, RRSIG, NSEC,
and TYPE1234 RRsets associated with the name alfa.example.com.

The RDATA section of the NSEC RR above would be encoded as:

        0x04 'h'  'o'  's'  't'
        0x07 'e'  'x'  'a'  'm'  'p'  'l'  'e'
        0x03 'c'  'o'  'm'  0x00
        0x00 0x06 0x40 0x01 0x00 0x00 0x00 0x03
        0x04 0x1b 0x00 0x00 0x00 0x00 0x00 0x00
        0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
        0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
        0x00 0x00 0x00 0x00 0x20

Assuming that the validator can authenticate this NSEC record, it
could be used to prove that beta.example.com does not exist, or to
prove that there is no AAAA record associated with alfa.example.com.
Authenticated denial of existence is discussed in [x.x.x].

## RR TYPE 48 - DNSKEY

      0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    Flags                      |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |        Protocol       |       Algorithm       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                                               /
    /                  Public Key                   /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

DNSSEC uses public key cryptography to sign and authenticate DNS
resource record sets (RRsets). The public keys are stored in DNSKEY
resource records and are used in the DNSSEC authentication process
described in [x.x.x]: A zone signs its authoritative RRsets by
using a private key and stores the corresponding public key in a
DNSKEY RR. A resolver can then use the public key to validate
signatures covering the RRsets in the zone, and thus to authenticate
them.

The DNSKEY RR is not intended as a record for storing arbitrary
public keys and MUST NOT be used to store certificates or public keys
that do not directly relate to the DNS infrastructure.

The Type value for the DNSKEY RR type is 48.

The DNSKEY RR is class independent.

The DNSKEY RR has no special TTL requirements.

### The Flags Field

Bit 7 of the Flags field is the Zone Key flag. If bit 7 has value 1,
then the DNSKEY record holds a DNS zone key, and the DNSKEY RR's
owner name MUST be the name of a zone. If bit 7 has value 0, then
the DNSKEY record holds some other type of DNS public key and MUST
NOT be used to verify RRSIGs that cover RRsets.

Bit 15 of the Flags field is the Secure Entry Point (SEP) flag, described
in [RFC-3757](https://ietf.org/rfc/rfc3757.txt). If bit 15 has value 1, then the DNSKEY record holds a
key intended for use as a secure entry point. This flag is only
intended to be a hint to zone signing or debugging software as to the
intended use of this DNSKEY record; validators MUST NOT alter their
behavior during the signature validation process in any way based on
the setting of this bit. This also means that a DNSKEY RR with the
SEP bit set would also need the Zone Key flag set in order to be able
to generate signatures legally. A DNSKEY RR with the SEP set and the
Zone Key flag not set MUST NOT be used to verify RRSIGs that cover
RRsets.

Bits 0-6 and 8-14 are reserved: these bits MUST have value 0 upon
creation of the DNSKEY RR and MUST be ignored upon receipt.

### The Protocol Field

The Protocol Field MUST have value 3, and the DNSKEY RR MUST be
treated as invalid during signature verification if it is found to be
some value other than 3.

Although the Protocol Field always has value 3, it is retained for
backward compatibility with early versions of the KEY record.

### The Algorithm Field

The Algorithm field identifies the public key's cryptographic
algorithm and determines the format of the Public Key field. A list
of DNSSEC algorithm types can be found in [x.x.x].

### The Public Key Field

The Public Key Field holds the public key material. The format
depends on the algorithm of the key being stored and is described [x.x.x].

### The DNSKEY RR Presentation Format

The presentation format of the RDATA portion is as follows:

The Flag field MUST be represented as an unsigned decimal integer.
Given the currently defined flags, the possible values are: 0, 256,
and 257.

The Protocol Field MUST be represented as an unsigned decimal integer
with a value of 3.

The Algorithm field MUST be represented either as an unsigned decimal
integer or as an algorithm mnemonic as specified in [x.x.x].

The Public Key field MUST be represented as a Base64 encoding of the
Public Key. Whitespace is allowed within the Base64 text. For a
definition of Base64 encoding, see [RFC-3548](https://ietf.org/rfc/rfc3548.txt).

The following DNSKEY RR stores a DNS zone key for example.com.

example.com. 86400 IN DNSKEY 256 3 5 ( AQPSKmynfzW4kyBv015MUG2DeIQ3
                                        Cbl+BBZH4b/0PY1kxkmvHjcZc8no
                                        kfzj31GajIQKY+5CptLr3buXA10h
                                        WqTkF7H6RfoRqXQeogmMHfpftf6z
                                        Mv1LyBUgia7za6ZEzOJBOztyvhjL
                                        742iU/TpPSEDhm2SNKLijfUppn1U
                                        aNvv4w==  )

The first four text fields specify the owner name, TTL, Class, and RR
type (DNSKEY). Value 256 indicates that the Zone Key bit (bit 7) in
the Flags field has value 1. Value 3 is the fixed Protocol value.
Value 5 indicates the public key algorithm. [x.x.x] identifies
algorithm type 5 as RSA/SHA1 and indicates that the format of the
RSA/SHA1 public key field is defined in [RFC-3110](https://ietf.org/rfc/rfc3110.txt). The remaining
text is a Base64 encoding of the public key.

## Resource Record Sets

Each resource record has a label, class, type, and data. It is meaningless
for two records to ever have label, class, type, and data to all be equal -
servers should suppress such duplicates if encountered. It is however possible
for most record types to exist with the same label, class, and type, but with
different data. Such a group of records is defines as a Resource Record Set (RRSet).

### TTLs of RRs in an RRSet

The TTLs of all RRs in an RRSet MUST be the same.

Should a client receive a response containing RRs from an RRSet with
differing TTLs, it should treat this as an error. If the RRSet concerned
is from a non-authoritative source for this data, the client should simply
ignore the RRSet, and if the values were required, seek to acquire them from
an authoritative source. Clients that are configured to send all queries to one,
or more, particular servers should treat those servers as authoritative for this
purpose. Should an authoritative source send such a malformed RRSet, the client
should treat the RRs for all purposes as if all TTLs in the RRSet had been
set to the value of the lowest TTL in the RRSet.

### Receiving RRSets

Servers must never merge RRs from a response with RRs in their cache
to form an RRSet. If a response contains data that would form an
RRSet with data in a server's cache the server must either ignore the
RRs in the response, or discard the entire RRSet currently in the
cache, as appropriate. Consequently the issue of TTLs varying
between the cache and a response does not cause concern, one will be
ignored. That is, one of the data sets is always incorrect if the
data from an answer differs from the data in the cache. The
challenge for the server is to determine which of the data sets is
correct, if one is, and retain that, while ignoring the other. Note
that if a server receives an answer containing an RRSet that is
identical to that in its cache, with the possible exception of the
TTL value, it may, optionally, update the TTL in its cache with the
TTL of the received answer. It should do this if the received answer
would be considered more authoritative (as discussed in the next
section) than the previously cached answer.

#### Ranking Data

When considering whether to accept an RRSet in a reply, or retain an
RRSet already in its cache instead, a server should consider the
relative likely trustworthiness of the various data. An
authoritative answer from a reply should replace cached data that had
been obtained from additional information in an earlier reply.
However additional information from a reply will be ignored if the
cache contains data from an authoritative answer or a zone file.

The accuracy of data available is assumed from its source.
Trustworthiness shall be, in order from most to least:

    + Data from a primary zone file, other than glue data,
    + Data from a zone transfer, other than glue,
    + The authoritative data included in the answer section of an
    authoritative reply.
    + Data from the authority section of an authoritative answer,
    + Glue from a primary zone, or glue from a zone transfer,
    + Data from the answer section of a non-authoritative answer, and
    non-authoritative data from the answer section of authoritative
    answers,
    + Additional information from an authoritative answer,
    Data from the authority section of a non-authoritative answer,
    Additional information from non-authoritative answers.

Note that the answer section of an authoritative answer normally
contains only authoritative data. However when the name sought is an
alias (see section 10.1.1) only the record describing that alias is
necessarily authoritative. Clients should assume that other records
may have come from the server's cache. Where authoritative answers
are required, the client should query again, using the canonical name
associated with the alias.

Unauthenticated RRs received and cached from the least trustworthy of
those groupings, that is data from the additional data section, and
data from the authority section of a non-authoritative answer, should
not be cached in such a way that they would ever be returned as
answers to a received query. They may be returned as additional
information where appropriate. Ignoring this would allow the
trustworthiness of relatively untrustworthy data to be increased
without cause or excuse.

When DNSSEC is in use, and an authenticated reply has
been received and verified, the data thus authenticated shall be
considered more trustworthy than unauthenticated data of the same
type. Note that throughout this document, "authoritative" means a
reply with the AA bit set. DNSSEC uses trusted chains of SIG and KEY
records to determine the authenticity of data, the AA bit is almost
irrelevant. However DNSSEC aware servers must still correctly set
the AA bit in responses to enable correct operation with servers that
are not security aware.

Note that, glue excluded, it is impossible for data from two
correctly configured primary zone files, two correctly configured
secondary zones (data from zone transfers) or data from correctly
configured primary and secondary zones to ever conflict. Where glue
for the same name exists in multiple zones, and differs in value, the
nameserver should select data from a primary zone file in preference
to secondary, but otherwise may choose any single set of such data.
Choosing that which appears to come from a source nearer the
authoritative data source may make sense where that can be
determined. Choosing primary data over secondary allows the source
of incorrect glue data to be discovered more readily, when a problem
with such data exists. Where a server can detect from two zone files
that one or more are incorrectly configured, so as to create
conflicts, it should refuse to load the zones determined to be
erroneous, and issue suitable diagnostics.

"Glue" above includes any record in a zone file that is not properly
part of that zone, including nameserver records of delegated sub-
zones (NS records), address records that accompany those NS records
(A, AAAA, etc), and any other stray data that might appear.

### Sending RRSets

A Resource Record Set should only be included once in any DNS reply.
It may occur in any of the Answer, Authority, or Additional
Information sections, as required. However it should not be repeated
in the same, or any other, section, except where explicitly required
by a specification. For example, an AXFR response requires the SOA
record (always an RRSet containing a single RR) be both the first and
last record of the reply. Where duplicates are required this way,
the TTL transmitted in each case must be the same.

## Canonical Form and Order of Resource Records

This section defines a canonical form for resource records, a
canonical ordering of DNS names, and a canonical ordering of resource
records within an RRset. A canonical name order is required to
construct the NSEC name chain. A canonical RR form and ordering
within an RRset are required in order to construct and verify RRSIG
RRs.

### Canonical DNS Name Order

For the purposes of DNS security, owner names are ordered by treating
individual labels as unsigned left-justified octet strings. The
absence of a octet sorts before a zero value octet, and uppercase
US-ASCII letters are treated as if they were lowercase US-ASCII
letters.

To compute the canonical ordering of a set of DNS names, start by
sorting the names according to their most significant (rightmost)
labels. For names in which the most significant label is identical,
continue sorting according to their next most significant label, and
so forth.

For example, the following names are sorted in canonical DNS name
order. The most significant label is "example". At this level,
"example" sorts first, followed by names ending in "a.example", then
by names ending "z.example". The names within each level are sorted
in the same way.

            example
            a.example
            yljkjljk.a.example
            Z.a.example
            zABC.a.EXAMPLE
            z.example
            \001.z.example
            *.z.example
            \200.z.example

### Canonical RR Form

For the purposes of DNS security, the canonical form of an RR is the
wire format of the RR where:

1. every domain name in the RR is fully expanded (no DNS name
    compression) and fully qualified;

2. all uppercase US-ASCII letters in the owner name of the RR are
    replaced by the corresponding lowercase US-ASCII letters;

3. if the type of the RR is NS, MD, MF, CNAME, SOA, MB, MG, MR, PTR,
    HINFO, MINFO, MX, HINFO, RP, AFSDB, RT, SIG, PX, NXT, NAPTR, KX,
    SRV, DNAME, A6, RRSIG, or NSEC, all uppercase US-ASCII letters in
    the DNS names contained within the RDATA are replaced by the
    corresponding lowercase US-ASCII letters;

4. if the owner name of the RR is a wildcard name, the owner name is
    in its original unexpanded form, including the "*" label (no
    wildcard substitution); and

5. the RR's TTL is set to its original value as it appears in the
    originating authoritative zone or the Original TTL field of the
    covering RRSIG RR.

### Canonical RR Ordering within an RRSet

For the purposes of DNS security, RRs with the same owner name,
class, and type are sorted by treating the RDATA portion of the
canonical form of each RR as a left-justified unsigned octet sequence
in which the absence of an octet sorts before a zero octet.

[RFC-2181](https://ietf.org/rfc/rfc2181.txt) specifies that an RRset is not allowed to contain duplicate
records (multiple RRs with the same owner name, class, type, and
RDATA). Therefore, if an implementation detects duplicate RRs when
putting the RRset in canonical form, it MUST treat this as a protocol
error. If the implementation chooses to handle this protocol error
in the spirit of the robustness principle (being liberal in what it
accepts), it MUST remove all but one of the duplicate RR(s) for the
purposes of calculating the canonical form of the RRset.

# Special Purpose Domains

## IN-ADDR.ARPA Domain

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



## IP6.ARPA Domain

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
In response to this, the backward-compatible Extension Mechanisms for DNS (EDNS(`0`))
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
4-bit OPCODE, a 4-bit RCODE, and a number of 1-bit flags (see [Header Format]). Some of these flag values were marked for
future use, and most of these have since been allocated. Also, most
of the RCODE values are now in use. The OPT pseudo-RR specified
below contains extensions to the RCODE bit field as well as
additional flag bits.

### UDP Message Size

Traditional DNS messages are limited to 512 octets in size when sent
over UDP (see [Size Limits]). Fitting the increasing amounts of data that can
be transported in DNS in this 512-byte limit is becoming more
difficult. For instance, inclusion of DNSSEC records frequently
requires a much larger response than a 512-byte message can hold.

EDNS(`0`) specifies a way to advertise additional features such as
larger response size capability, which is intended to help avoid
truncated UDP responses, which in turn cause retry over TCP. It
therefore provides support for transporting these larger packet sizes
without needing to resort to TCP for transport.

### The OPT Psuedo-RR

The main change in EDNS(`0`) is the addition of the OPT "psuedo"-RR. This addition is
detailed in [RR TYPE 41 - OPT].

# DNSSEC

Historically, there has been no way to validate the data retrieved from
the DNS, or ensure server to server communications are not tampered on the wire.
The Domain Name System Security Extensions (DNSSEC) add data origin
authentication and data integrity to the Domain Name System. This section intoduces
these extensions and describes their capabilities and limitations. This
section also discusses the services that the DNS security extensions
do and do not provide. Last, this section describes the interrelationships
between the documents that collectively describe DNSSEC.

Three RFCs form the current definition of DNSSEC as it is today. These RFCs are
[RFC-4033](https://www.ietf.org/rfc/rfc4033.txt), [RFC-4034](https://www.ietf.org/rfc/rfc4034.txt), and [RFC-4035](https://www.ietf.org/rfc/rfc4035.txt). These documents update, clarify, and refine the
security extensions defined in previous RFCs. These security extensions consist of
a set of new resource record types and modifications to the existing DNS protocol.

The DNS security extensions provide origin authentication and
integrity protection for DNS data, as well as a means of public key
distribution. These extensions do not provide confidentiality.

## DNSSEC Security Introduction and Requirements

### Definitions of Important DNSSEC Terms

This section servers as a glossary of important DNSSEC terms. This is intended to be useful
as a reference, first time readers may wish to skim this section quickly, read the rest of
the DNSSEC sections, and then come back to this section.

   **Authentication Chain**: An alternating sequence of DNS public key
      (DNSKEY) RRsets and Delegation Signer (DS) RRsets forms a chain of
      signed data, with each link in the chain vouching for the next. A
      DNSKEY RR is used to verify the signature covering a DS RR and
      allows the DS RR to be authenticated. The DS RR contains a hash
      of another DNSKEY RR and this new DNSKEY RR is authenticated by
      matching the hash in the DS RR. This new DNSKEY RR in turn
      authenticates another DNSKEY RRset and, in turn, some DNSKEY RR in
      this set may be used to authenticate another DS RR, and so forth
      until the chain finally ends with a DNSKEY RR whose corresponding
      private key signs the desired DNS data. For example, the root
      DNSKEY RRset can be used to authenticate the DS RRset for
      "example."  The "example." DS RRset contains a hash that matches
      some "example." DNSKEY, and this DNSKEY's corresponding private
      key signs the "example." DNSKEY RRset. Private key counterparts
      of the "example." DNSKEY RRset sign data records such as
      "www.example." and DS RRs for delegations such as
      "subzone.example."

   **Authentication Key**: A public key that a security-aware resolver has
      verified and can therefore use to authenticate data. A
      security-aware resolver can obtain authentication keys in three
      ways. First, the resolver is generally configured to know about
      at least one public key; this configured data is usually either
      the public key itself or a hash of the public key as found in the
      DS RR (see "trust anchor"). Second, the resolver may use an
      authenticated public key to verify a DS RR and the DNSKEY RR to
      which the DS RR refers. Third, the resolver may be able to
      determine that a new public key has been signed by the private key
      corresponding to another public key that the resolver has
      verified. Note that the resolver must always be guided by local
      policy when deciding whether to authenticate a new public key,
      even if the local policy is simply to authenticate any new public
      key for which the resolver is able verify the signature.

   **Authoritative RRset**: Within the context of a particular zone, an
      RRset is "authoritative" if and only if the owner name of the
      RRset lies within the subset of the name space that is at or below
      the zone apex and at or above the cuts that separate the zone from
      its children, if any. All RRsets at the zone apex are
      authoritative, except for certain RRsets at this domain name that,
      if present, belong to this zone's parent. These RRset could
      include a DS RRset, the NSEC RRset referencing this DS RRset (the
      "parental NSEC"), and RRSIG RRs associated with these RRsets, all
      of which are authoritative in the parent zone. Similarly, if this
      zone contains any delegation points, only the parental NSEC RRset,
      DS RRsets, and any RRSIG RRs associated with these RRsets are
      authoritative for this zone.

   **Delegation Point**: Term used to describe the name at the parental side
      of a zone cut. That is, the delegation point for "foo.example"
      would be the foo.example node in the "example" zone (as opposed to
      the zone apex of the "foo.example" zone). See also zone apex.

   **Island of Security**: Term used to describe a signed, delegated zone
      that does not have an authentication chain from its delegating
      parent. That is, there is no DS RR containing a hash of a DNSKEY
      RR for the island in its delegating parent zone.
      An island of security is served by security-aware name servers and
      may provide authentication chains to any delegated child zones.
      Responses from an island of security or its descendents can only
      be authenticated if its authentication keys can be authenticated
      by some trusted means out of band from the DNS protocol.

   **Key Signing Key (KSK)**: An authentication key that corresponds to a
      private key used to sign one or more other authentication keys for
      a given zone. Typically, the private key corresponding to a key
      signing key will sign a zone signing key, which in turn has a
      corresponding private key that will sign other zone data. Local
      policy may require that the zone signing key be changed
      frequently, while the key signing key may have a longer validity
      period in order to provide a more stable secure entry point into
      the zone. Designating an authentication key as a key signing key
      is purely an operational issue: DNSSEC validation does not
      distinguish between key signing keys and other DNSSEC
      authentication keys, and it is possible to use a single key as
      both a key signing key and a zone signing key. Key signing keys
      are discussed in more detail in [RFC-3757](https://ietf.org/rfc/rfc3757.txt). Also see zone signing
      key.

   **Non-Validating Security-Aware Stub Resolver**: A security-aware stub
      resolver that trusts one or more security-aware recursive name
      servers to perform most of the tasks discussed in this document
      set on its behalf. In particular, a non-validating security-aware
      stub resolver is an entity that sends DNS queries, receives DNS
      responses, and is capable of establishing an appropriately secured
      channel to a security-aware recursive name server that will
      provide these services on behalf of the security-aware stub
      resolver. See also security-aware stub resolver, validating
      security-aware stub resolver.

   **Non-Validating Stub Resolver**: A less tedious term for a
      non-validating security-aware stub resolver.

   **Security-Aware Name Server**: An entity acting in the role of a name
      server that understands the
      DNS security extensions defined in this document set. In
      particular, a security-aware name server is an entity that
      receives DNS queries, sends DNS responses, supports the EDNS(`0`)
      message size extension and the DO bit, and
      supports the RR types and message header bits defined in this
      document set.

   **Security-Aware Recursive Name Server**: An entity that acts in both the
      security-aware name server and security-aware resolver roles. A
      more cumbersome but equivalent phrase would be "a security-aware
      name server that offers recursive service".

   **Security-Aware Resolver**: An entity acting in the role of a resolver
      that understands the DNS
      security extensions defined in this document set. In particular,
      a security-aware resolver is an entity that sends DNS queries,
      receives DNS responses, supports the EDNS(`0`) message
      size extension and the DO bit, and is capable of using
      the RR types and message header bits defined in this document set
      to provide DNSSEC services.

   **Security-Aware Stub Resolver**: An entity acting in the role of a stub
      resolver that has enough
      of an understanding the DNS security extensions defined in this
      document set to provide additional services not available from a
      security-oblivious stub resolver. Security-aware stub resolvers
      may be either "validating" or "non-validating", depending on
      whether the stub resolver attempts to verify DNSSEC signatures on
      its own or trusts a friendly security-aware name server to do so.
      See also validating stub resolver, non-validating stub resolver.

   **Security-Oblivious \<anything\>**: An \<anything\> that is not
      "security-aware".

   **Signed Zone**: A zone whose RRsets are signed and that contains
      properly constructed DNSKEY, Resource Record Signature (RRSIG),
      Next Secure (NSEC), and (optionally) DS records.

   **Trust Anchor**: A configured DNSKEY RR or DS RR hash of a DNSKEY RR. A
      validating security-aware resolver uses this public key or hash as
      a starting point for building the authentication chain to a signed
      DNS response. In general, a validating resolver will have to
      obtain the initial values of its trust anchors via some secure or
      trusted means outside the DNS protocol. Presence of a trust
      anchor also implies that the resolver should expect the zone to
      which the trust anchor points to be signed.

   **Unsigned Zone**: A zone that is not signed.

   **Validating Security-Aware Stub Resolver**: A security-aware resolver
      that sends queries in recursive mode but that performs signature
      validation on its own rather than just blindly trusting an
      upstream security-aware recursive name server. See also
      security-aware stub resolver, non-validating security-aware stub
      resolver.

   **Validating Stub Resolver**: A less tedious term for a validating
      security-aware stub resolver.

   **Zone Apex**: Term used to describe the name at the child's side of a
      zone cut. See also delegation point.

   **Zone Signing Key (ZSK)**: An authentication key that corresponds to a
      private key used to sign a zone. Typically, a zone signing key
      will be part of the same DNSKEY RRset as the key signing key whose
      corresponding private key signs this DNSKEY RRset, but the zone
      signing key is used for a slightly different purpose and may
      differ from the key signing key in other ways, such as validity
      lifetime. Designating an authentication key as a zone signing key
      is purely an operational issue; DNSSEC validation does not
      distinguish between zone signing keys and other DNSSEC
      authentication keys, and it is possible to use a single key as
      both a key signing key and a zone signing key. See also key
      signing key.

### Services Provided by DNSSEC

The Domain Name System (DNS) security extensions provide origin
authentication and integrity assurance services for DNS data,
including mechanisms for authenticated denial of existence of DNS
data. These mechanisms are described below.

These mechanisms require changes to the DNS protocol. DNSSEC adds
four new resource record types: Resource Record Signature (RRSIG),
DNS Public Key (DNSKEY), Delegation Signer (DS), and Next Secure
(NSEC). It also adds two new message header bits: Checking Disabled
(CD) and Authenticated Data (AD). In order to support the larger DNS
message sizes that result from adding the DNSSEC RRs, DNSSEC also
requires [EDNS(`0`)] support. Finally, DNSSEC requires support
for the DNSSEC OK (DO) EDNS header bit (see [OPT Record TTL Field Use] for its location) so that a
security-aware resolver can indicate in its queries that it wishes to
receive DNSSEC RRs in response messages.

Please see [x.x.x] for a discussion of the limitations of these extensions.

#### Data Origin Authentication and Data Integrity

DNSSEC provides authentication by associating cryptographically
generated digital signatures with DNS RRsets. These digital
signatures are stored in a new resource record, the RRSIG record.
Typically, there will be a single private key that signs a zone's
data, but multiple keys are possible. For example, there may be keys
for each of several different digital signature algorithms. If a
security-aware resolver reliably learns a zone's public key, it can
authenticate that zone's signed data. An important DNSSEC concept is
that the key that signs a zone's data is associated with the zone
itself and not with the zone's authoritative name servers. (Public
keys for DNS transaction authentication mechanisms may also appear in
zones, as described in [RFC-2931](https://ietf.org/rfc/rfc2931.txt), but DNSSEC itself is concerned with
object security of DNS data, not channel security of DNS
transactions. The keys associated with transaction security may be
stored in different RR types. See [RFC-3755](https://ietf.org/rfc/rfc3755.txt) for details.)

A security-aware resolver can learn a zone's public key either by
having a trust anchor configured into the resolver or by normal DNS
resolution. To allow the latter, public keys are stored in a new
type of resource record, the DNSKEY RR. Note that the private keys
used to sign zone data must be kept secure and should be stored
offline when practical. To discover a public key reliably via DNS
resolution, the target key itself has to be signed by either a
configured authentication key or another key that has been
authenticated previously. Security-aware resolvers authenticate zone
information by forming an authentication chain from a newly learned
public key back to a previously known authentication public key,
which in turn either has been configured into the resolver or must
have been learned and verified previously. Therefore, the resolver
must be configured with at least one trust anchor.

If the configured trust anchor is a zone signing key, then it will
authenticate the associated zone; if the configured key is a key
signing key, it will authenticate a zone signing key. If the
configured trust anchor is the hash of a key rather than the key
itself, the resolver may have to obtain the key via a DNS query. To
help security-aware resolvers establish this authentication chain,
security-aware name servers attempt to send the signature(s) needed
to authenticate a zone's public key(s) in the DNS reply message along
with the public key itself, provided that there is space available in
the message.

The Delegation Signer (DS) RR type simplifies some of the
administrative tasks involved in signing delegations across
organizational boundaries. The DS RRset resides at a delegation
point in a parent zone and indicates the public key(s) corresponding
to the private key(s) used to self-sign the DNSKEY RRset at the
delegated child zone's apex. The administrator of the child zone, in
turn, uses the private key(s) corresponding to one or more of the
public keys in this DNSKEY RRset to sign the child zone's data. The
typical authentication chain is therefore
DNSKEY->\[DS->DNSKEY\]\*->RRset, where "\*" denotes zero or more
DS->DNSKEY subchains. DNSSEC permits more complex authentication
chains, such as additional layers of DNSKEY RRs signing other DNSKEY
RRs within a zone.

A security-aware resolver normally constructs this authentication
chain from the root of the DNS hierarchy down to the leaf zones based
on configured knowledge of the public key for the root. Local
policy, however, may also allow a security-aware resolver to use one
or more configured public keys (or hashes of public keys) other than
the root public key, may not provide configured knowledge of the root
public key, or may prevent the resolver from using particular public
keys for arbitrary reasons, even if those public keys are properly
signed with verifiable signatures. DNSSEC provides mechanisms by
which a security-aware resolver can determine whether an RRset's
signature is "valid" within the meaning of DNSSEC. In the final
analysis, however, authenticating both DNS keys and data is a matter
of local policy, which may extend or even override the protocol
extensions defined in this document set. See [x.x.x] for further
discussion.

#### Authenticating Name and Type Non-Existence

The security mechanism described in [Data Origin Authentication and Data Integrity] only provides a way
to sign existing RRsets in a zone. The problem of providing negative
responses with the same level of authentication and integrity
requires the use of another new resource record type, the NSEC
record. The NSEC record allows a security-aware resolver to
authenticate a negative reply for either name or type non-existence
with the same mechanisms used to authenticate other DNS replies. Use
of NSEC records requires a canonical representation and ordering for
domain names in zones. Chains of NSEC records explicitly describe
the gaps, or "empty space", between domain names in a zone and list
the types of RRsets present at existing names. Each NSEC record is
signed and authenticated using the mechanisms described in [Data Origin Authentication and Data Integrity].

### Services Not Provided by DNSSEC

DNS was originally designed with the assumptions that the DNS will
return the same answer to any given query regardless of who may have
issued the query (in practice this does not hold up, a nameserver might choose to include random A glue records in order to perform load balancing for example), and that all data in the DNS is thus visible.
Accordingly, DNSSEC is not designed to provide confidentiality,
access control lists, or other means of differentiating between
inquirers.

DNSSEC provides no protection against denial of service attacks.
Security-aware resolvers and security-aware name servers are
vulnerable to an additional class of denial of service attacks based
on cryptographic operations. Please see [x.x.x] for details.

The DNS security extensions provide data and origin authentication
for DNS data. The mechanisms outlined above are not designed to
protect operations such as zone transfers and dynamic update.
Message authentication schemes described in [RFC-2845](https://ietf.org/rfc/rfc2845.txt) and [RFC-2931](https://ietf.org/rfc/rfc2931.txt) address security operations that pertain to
these transactions.

### Scope of the DNSSEC Document Set and Last Hop Issues

The specification in the DNSSEC document set defines the behavior for zone
signers and security-aware name servers and resolvers in such a way
that the validating entities can unambiguously determine the state of
the data.

A validating resolver can determine the following 4 states:

   **Secure**: The validating resolver has a trust anchor, has a chain of
      trust, and is able to verify all the signatures in the response.

   **Insecure**: The validating resolver has a trust anchor, a chain of
      trust, and, at some delegation point, signed proof of the
      non-existence of a DS record. This indicates that subsequent
      branches in the tree are provably insecure. A validating resolver
      may have a local policy to mark parts of the domain space as
      insecure.

   **Bogus**: The validating resolver has a trust anchor and a secure
      delegation indicating that subsidiary data is signed, but the
      response fails to validate for some reason: missing signatures,
      expired signatures, signatures with unsupported algorithms, data
      missing that the relevant NSEC RR says should be present, and so
      forth.

   **Indeterminate**: There is no trust anchor that would indicate that a
      specific portion of the tree is secure. This is the default
      operation mode.

This specification only defines how security-aware name servers can
signal non-validating stub resolvers that data was found to be bogus
(using RCODE=2, "Server Failure"; see [x.x.x]).

There is a mechanism for security-aware name servers to signal
security-aware stub resolvers that data was found to be secure (using
the AD bit; see [x.x.x]).

This specification does not define a format for communicating why
responses were found to be bogus or marked as insecure. The current
signaling mechanism does not distinguish between indeterminate and
insecure states.

A method for signaling advanced error codes and policy between a
security-aware stub resolver and security-aware recursive nameservers
is a topic for future work, as is the interface between a security-
aware resolver and the applications that use it. Note, however, that
the lack of the specification of such communication does not prohibit
deployment of signed zones or the deployment of security aware
recursive name servers that prohibit propagation of bogus data to the
applications.

### Resolver Considerations

A security-aware resolver has to be able to perform cryptographic
functions necessary to verify digital signatures using at least the
mandatory-to-implement algorithm(s). Security-aware resolvers must
also be capable of forming an authentication chain from a newly
learned zone back to an authentication key, as described above. This
process might require additional queries to intermediate DNS zones to
obtain necessary DNSKEY, DS, and RRSIG records. A security-aware
resolver should be configured with at least one trust anchor as the
starting point from which it will attempt to establish authentication
chains.

If a security-aware resolver is separated from the relevant
authoritative name servers by a recursive name server or by any sort
of intermediary device that acts as a proxy for DNS, and if the
recursive name server or intermediary device is not security-aware,
the security-aware resolver may not be capable of operating in a
secure mode. For example, if a security-aware resolver's packets are
routed through a network address translation (NAT) device that
includes a DNS proxy that is not security-aware, the security-aware
resolver may find it difficult or impossible to obtain or validate
signed DNS data. The security-aware resolver may have a particularly
difficult time obtaining DS RRs in such a case, as DS RRs do not
follow the usual DNS rules for ownership of RRs at zone cuts. Note
that this problem is not specific to NATs: any security-oblivious DNS
software of any kind between the security-aware resolver and the
authoritative name servers will interfere with DNSSEC.

If a security-aware resolver must rely on an unsigned zone or a name
server that is not security aware, the resolver may not be able to
validate DNS responses and will need a local policy on whether to
accept unverified responses.

A security-aware resolver should take a signature's validation period
into consideration when determining the TTL of data in its cache, to
avoid caching signed data beyond the validity period of the
signature. However, it should also allow for the possibility that
the security-aware resolver's own clock is wrong. Thus, a
security-aware resolver that is part of a security-aware recursive
name server will have to pay careful attention to the DNSSEC
"checking disabled" (CD) bit (see [x.x.x]). This is in order to avoid
blocking valid signatures from getting through to other
security-aware resolvers that are clients of this recursive name
server. See [x.x.x] for how a secure recursive server handles
queries with the CD bit set.

### Stub Resolver Considerations

Although not strictly required to do so by the protocol, most DNS
queries originate from stub resolvers. Stub resolvers, by
definition, are minimal DNS resolvers that use recursive query mode
to offload most of the work of DNS resolution to a recursive name
server. Given the widespread use of stub resolvers, the DNSSEC
architecture has to take stub resolvers into account, but the
security features needed in a stub resolver differ in some respects
from those needed in a security-aware iterative resolver.

Even a security-oblivious stub resolver may benefit from DNSSEC if
the recursive name servers it uses are security-aware, but for the
stub resolver to place any real reliance on DNSSEC services, the stub
resolver must trust both the recursive name servers in question and
the communication channels between itself and those name servers.
The first of these issues is a local policy issue: in essence, a
security-oblivious stub resolver has no choice but to place itself at
the mercy of the recursive name servers that it uses, as it does not
perform DNSSEC validity checks on its own. The second issue requires
some kind of channel security mechanism; proper use of DNS
transaction authentication mechanisms such as SIG(`0`) ([RFC-2931](https://ietf.org/rfc/rfc2931.txt)) or
TSIG ([RFC-2845](https://ietf.org/rfc/rfc2845.txt)) would suffice, as would appropriate use of IPsec.
Particular implementations may have other choices available, such as
operating system specific interprocess communication mechanisms.
Confidentiality is not needed for this channel, but data integrity
and message authentication are.

A security-aware stub resolver that does trust both its recursive
name servers and its communication channel to them may choose to
examine the setting of the Authenticated Data (AD) bit in the message
header of the response messages it receives. The stub resolver can
use this flag bit as a hint to find out whether the recursive name
server was able to validate signatures for all of the data in the
Answer and Authority sections of the response.

There is one more step that a security-aware stub resolver can take
if, for whatever reason, it is not able to establish a useful trust
relationship with the recursive name servers that it uses: it can
perform its own signature validation by setting the Checking Disabled
(CD) bit in its query messages. A validating stub resolver is thus
able to treat the DNSSEC signatures as trust relationships between
the zone administrators and the stub resolver itself.

### Zone Considerations

There are several differences between signed and unsigned zones. A
signed zone will contain additional security-related records (RRSIG,
DNSKEY, DS, and NSEC records). RRSIG and NSEC records may be
generated by a signing process prior to serving the zone. The RRSIG
records that accompany zone data have defined inception and
expiration times that establish a validity period for the signatures
and the zone data the signatures cover.

#### TTL Values vs. RRSIG Validity Period

It is important to note the distinction between a RRset's TTL value
and the signature validity period specified by the RRSIG RR covering
that RRset. DNSSEC does not change the definition or function of the
TTL value, which is intended to maintain database coherency in
caches. A caching resolver purges RRsets from its cache no later
than the end of the time period specified by the TTL fields of those
RRsets, regardless of whether the resolver is security-aware.

The inception and expiration fields in the RRSIG RR (see [x.x.x]), on
the other hand, specify the time period during which the signature
can be used to validate the covered RRset. The signatures associated
with signed zone data are only valid for the time period specified by
these fields in the RRSIG RRs in question. TTL values cannot extend
the validity period of signed RRsets in a resolver's cache, but the
resolver may use the time remaining before expiration of the
signature validity period of a signed RRset as an upper bound for the
TTL of the signed RRset and its associated RRSIG RR in the resolver's
cache.

#### Temporal Dependency Issues for Zones

A signed zone requires regular maintenance to ensure that
each RRset in the zone has a current valid
RRSIG RR. The signature validity period of an RRSIG RR is an
interval during which the signature for one particular signed RRset
can be considered valid, and the signatures of different RRsets in a
zone may expire at different times. Re-signing one or more RRsets in
a zone will change one or more RRSIG RRs, which will in turn require
incrementing the zone's SOA serial number to indicate that a zone
change has occurred and re-signing the SOA RRset itself. Thus,
re-signing any RRset in a zone may also trigger DNS NOTIFY messages
and zone transfer operations.

### Name Server Considerations

A security-aware name server should include the appropriate DNSSEC
records (RRSIG, DNSKEY, DS, and NSEC) in all responses to queries
from resolvers that have signaled their willingness to receive such
records via use of the DO bit in the EDNS header, subject to message
size limitations. Because inclusion of these DNSSEC RRs could easily
cause UDP message truncation and fallback to TCP, a security-aware
name server must also support the EDNS "sender's UDP payload"
mechanism.

If possible, the private half of each DNSSEC key pair should be kept
offline, but this will not be possible for a zone for which DNS
dynamic update has been enabled. In the dynamic update case, the
primary master server for the zone will have to re-sign the zone when
it is updated, so the private key corresponding to the zone signing
key will have to be kept online. This is an example of a situation
in which the ability to separate the zone's DNSKEY RRset into zone
signing key(s) and key signing key(s) may be useful, as the key
signing key(s) in such a case can still be kept offline and may have
a longer useful lifetime than the zone signing key(s).

By itself, DNSSEC is not enough to protect the integrity of an entire
zone during zone transfer operations, as even a signed zone contains
some unsigned, nonauthoritative data if the zone has any children.
Therefore, zone maintenance operations will require some additional
mechanisms (most likely some form of channel security, such as TSIG,
SIG(`0`), or IPsec).

### Security Considerations

This document introduces DNS security extensions and describes the
document set that contains the new security records and DNS protocol
modifications. The extensions provide data origin authentication and
data integrity using digital signatures over resource record sets.
This section discusses the limitations of these extensions.

In order for a security-aware resolver to validate a DNS response,
all zones along the path from the trusted starting point to the zone
containing the response zones must be signed, and all name servers
and resolvers involved in the resolution process must be
security-aware, as defined in this document set. A security-aware
resolver cannot verify responses originating from an unsigned zone,
from a zone not served by a security-aware name server, or for any
DNS data that the resolver is only able to obtain through a recursive
name server that is not security-aware. If there is a break in the
authentication chain such that a security-aware resolver cannot
obtain and validate the authentication keys it needs, then the
security-aware resolver cannot validate the affected DNS data.

This document briefly discusses other methods of adding security to a
DNS query, such as using a channel secured by IPsec or using a DNS
transaction authentication mechanism such as TSIG ([RFC-2845](https://ietf.org/rfc/rfc2845.txt)) or
SIG(`0`) ([RFC-2931](https://ietf.org/rfc/rfc2931.txt)), but transaction security is not part of DNSSEC
per se.

A non-validating security-aware stub resolver, by definition, does
not perform DNSSEC signature validation on its own and thus is
vulnerable both to attacks on (and by) the security-aware recursive
name servers that perform these checks on its behalf and to attacks
on its communication with those security-aware recursive name
servers. Non-validating security-aware stub resolvers should use
some form of channel security to defend against the latter threat.
The only known defense against the former threat would be for the
security-aware stub resolver to perform its own signature validation,
at which point, again by definition, it would no longer be a
non-validating security-aware stub resolver.

DNSSEC does not protect against denial of service attacks. DNSSEC
makes DNS vulnerable to a new class of denial of service attacks
based on cryptographic operations against security-aware resolvers
and security-aware name servers, as an attacker can attempt to use
DNSSEC mechanisms to consume a victim's resources. This class of
attacks takes at least two forms. An attacker may be able to consume
resources in a security-aware resolver's signature validation code by
tampering with RRSIG RRs in response messages or by constructing
needlessly complex signature chains. An attacker may also be able to
consume resources in a security-aware name server that supports DNS
dynamic update, by sending a stream of update messages that force the
security-aware name server to re-sign some RRsets in the zone more
frequently than would otherwise be necessary.

Due to a deliberate design choice, DNSSEC does not provide
confidentiality.

DNSSEC introduces the ability for a hostile party to enumerate all
the names in a zone by following the NSEC chain. NSEC RRs assert
which names do not exist in a zone by linking from existing name to
existing name along a canonical ordering of all the names within a
zone. Thus, an attacker can query these NSEC RRs in sequence to
obtain all the names in a zone. Although this is not an attack on
the DNS itself, it could allow an attacker to map network hosts or
other resources by enumerating the contents of a zone.

DNSSEC introduces significant additional complexity to the DNS and
thus introduces many new opportunities for implementation bugs and
misconfigured zones. In particular, enabling DNSSEC signature
validation in a resolver may cause entire legitimate zones to become
effectively unreachable due to DNSSEC configuration errors or bugs.

DNSSEC does not protect against tampering with unsigned zone data.
Non-authoritative data at zone cuts (glue and NS RRs in the parent
zone) are not signed. This does not pose a problem when validating
the authentication chain, but it does mean that the non-authoritative
data itself is vulnerable to tampering during zone transfer
operations. Thus, while DNSSEC can provide data origin
authentication and data integrity for RRsets, it cannot do so for
zones, and other mechanisms (such as TSIG, SIG(`0`), or IPsec) must be
used to protect zone transfer operations.

## DNSSEC Algorithm and Digest Types

The DNS security extensions are designed to be independent of the
underlying cryptographic algorithms. The DNSKEY, RRSIG, and DS
resource records all use a DNSSEC Algorithm Number to identify the
cryptographic algorithm in use by the resource record. The DS
resource record also specifies a Digest Algorithm Number to identify
the digest algorithm used to construct the DS record. The currently
defined Algorithm and Digest Types are listed below. Additional
Algorithm or Digest Types could be added as advances in cryptography
warrant them.

A DNSSEC aware resolver or name server MUST implement all MANDATORY
algorithms.

### DNSSEC Algorithm Types

The DNSKEY, RRSIG, and DS RRs use an 8-bit number to identify the
security algorithm being used. These values are stored in the
"Algorithm number" field in the resource record RDATA.

Some algorithms are usable only for zone signing (DNSSEC), some only
for transaction security mechanisms (SIG(0) and TSIG), and some for
both. Those usable for zone signing may appear in DNSKEY, RRSIG, and
DS RRs. Those usable for transaction security would be present in
SIG(0) and KEY RRs, as described in [RFC-2931](https://ietf.org/rfc/rfc2931.txt).

| Value | Algorithm [Mnemonic] | Zone Signing | References | Status |
| ----- | -------------------- | ------------ | ---------- | ------ |
|   0   |       reserved       |              |            |        |
|   1   |    RSA/MD5 [RSAMD5]  | n | [RFC-2537](https://ietf.org/rfc/rfc2537.txt) | NOT RECOMMENDED |
|   2   |  Diffie-Hellman [DH] | n | [RFC-2539](https://ietf.org/rfc/rfc2539.txt) | - |
|   3   |    DSA/SHA-1 [DSA]   | y | [RFC-2536](https://ietf.org/rfc/rfc2536.txt) | OPTIONAL |
|   4   | Elliptic Curve [ECC] |   | TBA | - |
|   5   |  RSA/SHA-1 [RSASHA1] | y | [RFC-3110](https://ietf.org/rfc/rfc3110.txt) | MANDATORY |
|  252  |  Indirect [INDIRECT] | n |     | - |
|  253  | Private [PRIVATEDNS] | y | see below | OPTIONAL |
|  254  | Private [PRIVATEOID] | y | see below | OPTIONAL |
|  255  | reserved             |   |           |          |

Note values 6 - 251 are available for assignment by IETF Standards Action.

### Private Algorithm Types

Algorithm number 253 is reserved for private use and will never be
assigned to a specific algorithm. The public key area in the DNSKEY
RR and the signature area in the RRSIG RR begin with a wire encoded
domain name, which MUST NOT be compressed. The domain name indicates
the private algorithm to use, and the remainder of the public key
area is determined by that algorithm. Entities should only use
domain names they control to designate their private algorithms.

Algorithm number 254 is reserved for private use and will never be
assigned to a specific algorithm. The public key area in the DNSKEY
RR and the signature area in the RRSIG RR begin with an unsigned
length byte followed by a BER encoded Object Identifier (ISO OID) of
that length. The OID indicates the private algorithm in use, and the
remainder of the area is whatever is required by that algorithm.
Entities should only use OIDs they control to designate their private
algorithms.

### DNSSEC Digest Types

A "Digest Type" field in the DS resource record types identifies the
cryptographic digest algorithm used by the resource record. The
following table lists the currently defined digest algorithm types.

| VALUE | Algorithm  | STATUS |
| ----- | ---------  | ------ |
|   0   |  Reserved  |   -    |
|   1   |   SHA-1    | MANDATORY |
| 2-255 | Unassigned |   -    |

## Key Tag Calculation

The Key Tag field in the RRSIG and DS resource record types provides
a mechanism for selecting a public key efficiently. In most cases, a
combination of owner name, algorithm, and key tag can efficiently
identify a DNSKEY record. Both the RRSIG and DS resource records
have corresponding DNSKEY records. The Key Tag field in the RRSIG
and DS records can be used to help select the corresponding DNSKEY RR
efficiently when more than one candidate DNSKEY RR is available.

However, it is essential to note that the key tag is not a unique
identifier. It is theoretically possible for two distinct DNSKEY RRs
to have the same owner name, the same algorithm, and the same key
tag. The key tag is used to limit the possible candidate keys, but
it does not uniquely identify a DNSKEY record. Implementations MUST
NOT assume that the key tag uniquely identifies a DNSKEY RR.

The key tag is the same for all DNSKEY algorithm types except
algorithm 1 (please see [Key Tag for Algorithm 1 (RSA/MD5)] for the definition of the key
tag for algorithm 1). The key tag algorithm is the sum of the wire
format of the DNSKEY RDATA broken into 2 octet groups. First, the
RDATA (in wire format) is treated as a series of 2 octet groups.
These groups are then added together, ignoring any carry bits.

A reference implementation of the key tag algorithm is as an ANSI C
function is given below, with the RDATA portion of the DNSKEY RR is
used as input. It is not necessary to use the following reference
code verbatim, but the numerical value of the Key Tag MUST be
identical to what the reference implementation would generate for the
same input.

Please note that the algorithm for calculating the Key Tag is almost
but not completely identical to the familiar ones-complement checksum
used in many other Internet protocols. Key Tags MUST be calculated
using the algorithm described here rather than the ones complement
checksum.

The following ANSI C reference implementation calculates the value of
a Key Tag. This reference implementation applies to all algorithm
types except algorithm 1 (see [Key Tag for Algorithm 1 (RSA/MD5)]). The input is the wire
format of the RDATA portion of the DNSKEY RR. The code is written
for clarity, not efficiency.

```
    /*
    * Assumes that int is at least 16 bits.
    * First octet of the key tag is the most significant 8 bits of the
    * return value;
    * Second octet of the key tag is the least significant 8 bits of the
    * return value.
    */

    unsigned int
    keytag (
            unsigned char key[],  /* the RDATA part of the DNSKEY RR */
            unsigned int keysize  /* the RDLENGTH */
            )
    {
            unsigned long ac;     /* assumed to be 32 bits or larger */
            int i;                /* loop index */

            for ( ac = 0, i = 0; i < keysize; ++i )
                    ac += (i & 1) ? key[i] : key[i] << 8;
            ac += (ac >> 16) & 0xFFFF;
            return ac & 0xFFFF;
    }
```

### Key Tag for Algorithm 1 (RSA/MD5)

The key tag for algorithm 1 (RSA/MD5) is defined differently from the
key tag for all other algorithms, for historical reasons. For a
DNSKEY RR with algorithm 1, the key tag is defined to be the most
significant 16 bits of the least significant 24 bits in the public
key modulus (in other words, the 4th to last and 3rd to last octets
of the public key modulus).

Please note that Algorithm 1 is NOT RECOMMENDED.

## Zone Signing

DNSSEC introduces the concept of signed zones. A signed zone
includes DNS Public Key (DNSKEY), Resource Record Signature (RRSIG),
Next Secure (NSEC), and (optionally) Delegation Signer (DS) records
according to the rules specified in the respective following sections.
A zone that does not include these records according
to the rules in this section is an unsigned zone.

DNSSEC specifies the placement of two new RR types, NSEC and DS,
which can be placed at the parental side of a zone cut (that is, at a
delegation point). This is an exception to the general prohibition
against putting data in the parent zone at a zone cut. Section [x.x.x]
describes this change.

### Including DNSKEY RRs in a Zone

To sign a zone, the zone's administrator generates one or more
public/private key pairs and uses the private key(s) to sign
authoritative RRsets in the zone. For each private key used to
create RRSIG RRs in a zone, the zone SHOULD include a zone DNSKEY RR
containing the corresponding public key. A zone key DNSKEY RR MUST
have the Zone Key bit of the flags RDATA field set (see [The Flags Field]). Public keys associated with other DNS operations MAY
be stored in DNSKEY RRs that are not marked as zone keys but MUST NOT
be used to verify RRSIGs.

If the zone administrator intends a signed zone to be usable other
than as an island of security, the zone apex MUST contain at least
one DNSKEY RR to act as a secure entry point into the zone. This
secure entry point could then be used as the target of a secure
delegation via a corresponding DS RR in the parent zone.

### Including RRSIG RRs in a Zone

For each authoritative RRset in a signed zone, there MUST be at least
one RRSIG record that meets the following requirements:

*  The RRSIG owner name is equal to the RRset owner name.

*  The RRSIG class is equal to the RRset class.

*  The RRSIG Type Covered field is equal to the RRset type.

*  The RRSIG Original TTL field is equal to the TTL of the RRset.

*  The RRSIG RR's TTL is equal to the TTL of the RRset.

*  The RRSIG Labels field is equal to the number of labels in the
    RRset owner name, not counting the null root label and not
    counting the leftmost label if it is a wildcard.

*  The RRSIG Signer's Name field is equal to the name of the zone
    containing the RRset.

*  The RRSIG Algorithm, Signer's Name, and Key Tag fields identify a
    zone key DNSKEY record at the zone apex.

An RRset MAY have multiple RRSIG RRs
associated with it. Note that as RRSIG RRs are closely tied to the
RRsets whose signatures they contain, RRSIG RRs, unlike all other DNS
RR types, do not form RRsets. In particular, the TTL values among
RRSIG RRs with a common owner name do not follow the RRset rules
described in [x.x.x].

An RRSIG RR itself MUST NOT be signed, as signing an RRSIG RR would
add no value and would create an infinite loop in the signing
process.

The NS RRset that appears at the zone apex name MUST be signed, but
the NS RRsets that appear at delegation points (that is, the NS
RRsets in the parent zone that delegate the name to the child zone's
name servers) MUST NOT be signed. Glue address RRsets associated
with delegations MUST NOT be signed.

There MUST be an RRSIG for each RRset using at least one DNSKEY of
each algorithm in the zone apex DNSKEY RRset. The apex DNSKEY RRset
itself MUST be signed by each algorithm appearing in the DS RRset
located at the delegating parent (if any).

### Including NSEC RRs in a Zone

Each owner name in the zone that has authoritative data or a
delegation point NS RRset MUST have an NSEC resource record..

The TTL value for any NSEC RR SHOULD be the same as the minimum TTL
value field in the zone SOA RR.

An NSEC record (and its associated RRSIG RRset) MUST NOT be the only
RRset at any particular owner name. That is, the signing process
MUST NOT create NSEC or RRSIG RRs for owner name nodes that were not
the owner name of any RRset before the zone was signed. The main
reasons for this are a desire for namespace consistency between
signed and unsigned versions of the same zone and a desire to reduce
the risk of response inconsistency in security oblivious recursive
name servers.

The type bitmap of every NSEC resource record in a signed zone MUST
indicate the presence of both the NSEC record itself and its
corresponding RRSIG record.

The difference between the set of owner names that require RRSIG
records and the set of owner names that require NSEC records is
subtle and worth highlighting. RRSIG records are present at the
owner names of all authoritative RRsets. NSEC records are present at
the owner names of all names for which the signed zone is
authoritative and also at the owner names of delegations from the
signed zone to its children. Neither NSEC nor RRSIG records are
present (in the parent zone) at the owner names of glue address
RRsets. Note, however, that this distinction is for the most part
visible only during the zone signing process, as NSEC RRsets are
authoritative data and are therefore signed. Thus, any owner name
that has an NSEC RRset will have RRSIG RRs as well in the signed
zone.

The bitmap for the NSEC RR at a delegation point requires special
attention. Bits corresponding to the delegation NS RRset and any
RRsets for which the parent zone has authoritative data MUST be set;
bits corresponding to any non-NS RRset for which the parent is not
authoritative MUST be clear.

### Including DS RRs in a Zone

The DS resource record establishes authentication chains between DNS
zones. A DS RRset SHOULD be present at a delegation point when the
child zone is signed. The DS RRset MAY contain multiple records,
each referencing a public key in the child zone used to verify the
RRSIGs in that zone. All DS RRsets in a zone MUST be signed, and DS
RRsets MUST NOT appear at a zone's apex.

A DS RR SHOULD point to a DNSKEY RR that is present in the child's
apex DNSKEY RRset, and the child's apex DNSKEY RRset SHOULD be signed
by the corresponding private key. DS RRs that fail to meet these
conditions are not useful for validation, but because the DS RR and
its corresponding DNSKEY RR are in different zones, and because the
DNS is only loosely consistent, temporary mismatches can occur.

The TTL of a DS RRset SHOULD match the TTL of the delegating NS RRset
(that is, the NS RRset from the same zone containing the DS RRset).

Construction of a DS RR requires knowledge of the corresponding
DNSKEY RR in the child zone, which implies communication between the
child and parent zones. This communication is an operational matter
not covered by this document.

### DNSSEC RR Types Appearing at Zone Cuts

DNSSEC introduced two new RR types that are unusual in that they can
appear at the parental side of a zone cut. At the parental side of a
zone cut (that is, at a delegation point), NSEC RRs are REQUIRED at
the owner name. A DS RR could also be present if the zone being
delegated is signed and seeks to have a chain of authentication to
the parent zone. This is an exception to the original DNS
specification [RFC-1034](https://ietf.org/rfc/rfc1034.txt), which states that only NS RRsets could
appear at the parental side of a zone cut.
These RRsets are authoritative for the parent when they appear at the
parent side of a zone cut.

## Serving

This section describes the behavior of entities that include
security-aware name server functions. In many cases such functions
will be part of a security-aware recursive name server, but a
security-aware authoritative name server has some of the same
requirements. Functions specific to security-aware recursive name
servers are described in [x.x.x]; functions specific to
authoritative servers are described in [x.x.x].

In the following discussion, the terms "SNAME", "SCLASS", and "STYPE"
are as used in [x.x.x].

A security-aware name server MUST support the EDNS`0` (see [x.x.x])
message size extension, MUST support a message size of at least 1220
octets, and SHOULD support a message size of 4000 octets. As IPv6
packets can only be fragmented by the source host, a security aware
name server SHOULD take steps to ensure that UDP datagrams it
transmits over IPv6 are fragmented, if necessary, at the minimum IPv6
MTU, unless the path MTU is known. Please see [RFC-1122](https://ietf.org/rfc/rfc1122.txt), [RFC-2460](https://ietf.org/rfc/rfc2460.txt),
and [RFC-3226](https://ietf.org/rfc/rfc3226.txt) for further discussion of packet size and fragmentation
issues.


A security-aware name server that receives a DNS query that does not
include the EDNS OPT pseudo-RR or that has the DO bit clear MUST
treat the RRSIG, DNSKEY, and NSEC RRs as it would any other RRset and
MUST NOT perform any of the additional processing described below.
Because the DS RR type has the peculiar property of only existing in
the parent zone at delegation points, DS RRs always require some
special processing, as described in [x.x.x].

Security aware name servers that receive explicit queries for
security RR types that match the content of more than one zone that
it serves (for example, NSEC and RRSIG RRs above and below a
delegation point where the server is authoritative for both zones)
should behave self-consistently. As long as the response is always
consistent for each query to the name server, the name server MAY
return one of the following:

* The above-delegation RRsets.
* The below-delegation RRsets.
* Both above and below-delegation RRsets.
* Empty answer section (no records).
* Some other response.
* An error.

DNSSEC allocates two new bits in the DNS message header: the CD
(Checking Disabled) bit and the AD (Authentic Data) bit. The CD bit
is controlled by resolvers; a security-aware name server MUST copy
the CD bit from a query into the corresponding response. The AD bit
is controlled by name servers; a security-aware name server MUST
ignore the setting of the AD bit in queries. See [x.x.x],
[x.x.x], [x.x.x], [x.x.x], and [x.x.x] for details on the behavior of these bits.

A security aware name server that synthesizes CNAME RRs from DNAME
RRs as described in [x.x.x] SHOULD NOT generate signatures for the
synthesized CNAME RRs.

### Authoritative Name Servers

Upon receiving a relevant query that has the EDNS OPT
pseudo-RR DO bit (see [x.x.x]) set, a security-aware authoritative name
server for a signed zone MUST include additional RRSIG, NSEC, and DS
RRs, according to the following rules:

*  RRSIG RRs that can be used to authenticate a response MUST be
    included in the response according to the rules in [Including RRSIG RRs in a Response].

*  NSEC RRs that can be used to provide authenticated denial of
    existence MUST be included in the response automatically according
    to the rules in [Including NSEC RRs in a Response].

*  Either a DS RRset or an NSEC RR proving that no DS RRs exist MUST
    be included in referrals automatically according to the rules in
    [x.x.x].

These rules only apply to responses where the semantics convey
information about the presence or absence of resource records. That
is, these rules are not intended to rule out responses such as RCODE
4 ("Not Implemented") or RCODE 5 ("Refused").

DNSSEC does not change the DNS zone transfer protocol. [x.x.x]
discusses zone transfer requirements.

#### Including RRSIG RRs in a Response

When responding to a query that has the DO bit set, a security-aware
authoritative name server SHOULD attempt to send RRSIG RRs that a
security-aware resolver can use to authenticate the RRsets in the
response. A name server SHOULD make every attempt to keep the RRset
and its associated RRSIG(s) together in a response. Inclusion of
RRSIG RRs in a response is subject to the following rules:

*  When placing a signed RRset in the Answer section, the name server
    MUST also place its RRSIG RRs in the Answer section. The RRSIG
    RRs have a higher priority for inclusion than any other RRsets
    that may have to be included. If space does not permit inclusion
    of these RRSIG RRs, the name server MUST set the TC bit.

*  When placing a signed RRset in the Authority section, the name
    server MUST also place its RRSIG RRs in the Authority section.
    The RRSIG RRs have a higher priority for inclusion than any other
    RRsets that may have to be included. If space does not permit
    inclusion of these RRSIG RRs, the name server MUST set the TC bit.

*  When placing a signed RRset in the Additional section, the name
    server MUST also place its RRSIG RRs in the Additional section.
    If space does not permit inclusion of both the RRset and its
    associated RRSIG RRs, the name server MAY retain the RRset while
    dropping the RRSIG RRs. If this happens, the name server MUST NOT
    set the TC bit solely because these RRSIG RRs didn't fit.

#### Including DNSKEY RRs in a Response

When responding to a query that has the DO bit set and that requests
the SOA or NS RRs at the apex of a signed zone, a security-aware
authoritative name server for that zone MAY return the zone apex
DNSKEY RRset in the Additional section. In this situation, the
DNSKEY RRset and associated RRSIG RRs have lower priority than does
any other information that would be placed in the additional section.
The name server SHOULD NOT include the DNSKEY RRset unless there is
enough space in the response message for both the DNSKEY RRset and
its associated RRSIG RR(s). If there is not enough space to include
these DNSKEY and RRSIG RRs, the name server MUST omit them and MUST
NOT set the TC bit solely because these RRs didn't fit (see [Including RRSIG RRs in a Response]).

#### Including NSEC RRs in a Response

When responding to a query that has the DO bit set, a security-aware
authoritative name server for a signed zone MUST include NSEC RRs in
each of the following cases:

* No Data: The zone contains RRsets that exactly match \<SNAME, SCLASS\>
    but does not contain any RRsets that exactly match \<SNAME, SCLASS,
    STYPE\>.

* Name Error: The zone does not contain any RRsets that match \<SNAME,
    SCLASS\> either exactly or via wildcard name expansion.

* Wildcard Answer: The zone does not contain any RRsets that exactly
    match \<SNAME, SCLASS\> but does contain an RRset that matches
    \<SNAME, SCLASS, STYPE\> via wildcard name expansion.

* Wildcard No Data: The zone does not contain any RRsets that exactly
    match \<SNAME, SCLASS\> and does contain one or more RRsets that
    match \<SNAME, SCLASS\> via wildcard name expansion, but does not
    contain any RRsets that match \<SNAME, SCLASS, STYPE\> via wildcard
    name expansion.

In each of these cases, the name server includes NSEC RRs in the
response to prove that an exact match for \<SNAME, SCLASS, STYPE\> was
not present in the zone and that the response that the name server is
returning is correct given the data in the zone.

##### Including NSEC RRs: No Data Response

If the zone contains RRsets matching <SNAME, SCLASS> but contains no
RRset matching <SNAME, SCLASS, STYPE>, then the name server MUST
include the NSEC RR for <SNAME, SCLASS> along with its associated
RRSIG RR(s) in the Authority section of the response. If space does not permit inclusion of the NSEC RR or its
associated RRSIG RR(s), the name server MUST set the TC bit.

Since the search name exists, wildcard name expansion does not apply
to this query, and a single signed NSEC RR suffices to prove that the
requested RR type does not exist.

##### Including NSEC RRs: Name Error Response

If the zone does not contain any RRsets matching \<SNAME, SCLASS\>
either exactly or via wildcard name expansion, then the name server
MUST include the following NSEC RRs in the Authority section, along
with their associated RRSIG RRs:

*  An NSEC RR proving that there is no exact match for \<SNAME,
    SCLASS\>.

*  An NSEC RR proving that the zone contains no RRsets that would
    match \<SNAME, SCLASS\> via wildcard name expansion.

In some cases, a single NSEC RR may prove both of these points. If
it does, the name server SHOULD only include the NSEC RR and its
RRSIG RR(s) once in the Authority section.

If space does not permit inclusion of these NSEC and RRSIG RRs, the
name server MUST set the TC bit.

The owner names of these NSEC and RRSIG RRs are not subject to
wildcard name expansion when these RRs are included in the Authority
section of the response.

Note that this form of response includes cases in which SNAME
corresponds to an empty non-terminal name within the zone (a name
that is not the owner name for any RRset but that is the parent name
of one or more RRsets).

##### Including NSEC RRs: Wildcard Answer Response

If the zone does not contain any RRsets that exactly match <SNAME,
SCLASS> but does contain an RRset that matches <SNAME, SCLASS, STYPE>
via wildcard name expansion, the name server MUST include the
wildcard-expanded answer and the corresponding wildcard-expanded
RRSIG RRs in the Answer section and MUST include in the Authority
section an NSEC RR and associated RRSIG RR(s) proving that the zone
does not contain a closer match for <SNAME, SCLASS>. If space does
not permit inclusion of the answer, NSEC and RRSIG RRs, the name
server MUST set the TC bit.

##### Including NSEC RRs: Wildcard No Data Response

This case is a combination of the previous cases. The zone does not
contain an exact match for <SNAME, SCLASS>, and although the zone
does contain RRsets that match <SNAME, SCLASS> via wildcard
expansion, none of those RRsets matches STYPE. The name server MUST
include the following NSEC RRs in the Authority section, along with
their associated RRSIG RRs:

*  An NSEC RR proving that there are no RRsets matching STYPE at the
    wildcard owner name that matched <SNAME, SCLASS> via wildcard
    expansion.

*  An NSEC RR proving that there are no RRsets in the zone that would
    have been a closer match for <SNAME, SCLASS>.

In some cases, a single NSEC RR may prove both of these points. If
it does, the name server SHOULD only include the NSEC RR and its
RRSIG RR(s) once in the Authority section.

The owner names of these NSEC and RRSIG RRs are not subject to
wildcard name expansion when these RRs are included in the Authority
section of the response.

If space does not permit inclusion of these NSEC and RRSIG RRs, the
name server MUST set the TC bit.

##### Finding the Right NSEC RRs

As explained above, there are several situations in which a
security-aware authoritative name server has to locate an NSEC RR
that proves that no RRsets matching a particular SNAME exist.
Locating such an NSEC RR within an authoritative zone is relatively
simple, at least in concept. The following discussion assumes that
the name server is authoritative for the zone that would have held
the non-existent RRsets matching SNAME. The algorithm below is
written for clarity, not for efficiency.

To find the NSEC that proves that no RRsets matching name N exist in
the zone Z that would have held them, construct a sequence, S,
consisting of the owner names of every RRset in Z, sorted into
canonical order (see [x.x.x]), with no duplicate names. Find the name
M that would have immediately preceded N in S if any RRsets with
owner name N had existed. M is the owner name of the NSEC RR that
proves that no RRsets exist with owner name N.

The algorithm for finding the NSEC RR that proves that a given name
is not covered by any applicable wildcard is similar but requires an
extra step. More precisely, the algorithm for finding the NSEC
proving that no RRsets exist with the applicable wildcard name is
precisely the same as the algorithm for finding the NSEC RR that
proves that RRsets with any other owner name do not exist. The part
that's missing is a method of determining the name of the non-
existent applicable wildcard. In practice, this is easy, because the
authoritative name server has already checked for the presence of
precisely this wildcard name as part of step (1)(c) of the normal
lookup algorithm described in [x.x.x].


#### Including DS RRs in a Response

When responding to a query that has the DO bit set, a security-aware
authoritative name server returning a referral includes DNSSEC data
along with the NS RRset.

If a DS RRset is present at the delegation point, the name server
MUST return both the DS RRset and its associated RRSIG RR(s) in the
Authority section along with the NS RRset.

If no DS RRset is present at the delegation point, the name server
MUST return both the NSEC RR that proves that the DS RRset is not
present and the NSEC RR's associated RRSIG RR(s) along with the NS
RRset. The name server MUST place the NS RRset before the NSEC RRset
and its associated RRSIG RR(s).

Including these DS, NSEC, and RRSIG RRs increases the size of
referral messages and may cause some or all glue RRs to be omitted.
If space does not permit inclusion of the DS or NSEC RRset and
associated RRSIG RRs, the name server MUST set the TC bit.

##### Responding to Queries for DS RRs

The DS resource record type is unusual in that it appears only on the
parent zone's side of a zone cut. For example, the DS RRset for the
delegation of "foo.example" is stored in the "example" zone rather
than in the "foo.example" zone. This requires special processing
rules for both name servers and resolvers, as the name server for the
child zone is authoritative for the name at the zone cut by the
normal DNS rules but the child zone does not contain the DS RRset.
A security-aware resolver sends queries to the parent zone when
looking for a needed DS RR at a delegation point (see Section 4.2).
However, special rules are necessary to avoid confusing
security-oblivious resolvers which might become involved in
processing such a query (for example, in a network configuration that
forces a security-aware resolver to channel its queries through a
security-oblivious recursive name server). The rest of this section
describes how a security-aware name server processes DS queries in
order to avoid this problem.

The need for special processing by a security-aware name server only
arises when all the following conditions are met:

*  The name server has received a query for the DS RRset at a zone
    cut.

*  The name server is authoritative for the child zone.

*  The name server is not authoritative for the parent zone.

*  The name server does not offer recursion.

In all other cases, the name server either has some way of obtaining
the DS RRset or could not have been expected to have the DS RRset
even by the pre-DNSSEC processing rules, so the name server can
return either the DS RRset or an error response according to the
normal processing rules.

If all the above conditions are met, however, the name server is
authoritative for SNAME but cannot supply the requested RRset. In
this case, the name server MUST return an authoritative "no data"
response showing that the DS RRset does not exist in the child zone's
apex. See [x.x.x] for an example of such a response.

#### Responding to Queries for Type AXFR or IXFR

DNSSEC does not change the DNS zone transfer process. A signed zone
will contain RRSIG, DNSKEY, NSEC, and DS resource records, but these
records have no special meaning with respect to a zone transfer
operation.

An authoritative name server is not required to verify that a zone is
properly signed before sending or accepting a zone transfer.
However, an authoritative name server MAY choose to reject the entire
zone transfer if the zone fails to meet any of the signing
requirements described in [x.x.x]. The primary objective of a zone
transfer is to ensure that all authoritative name servers have
identical copies of the zone. An authoritative name server that
chooses to perform its own zone validation MUST NOT selectively
reject some RRs and accept others.

DS RRsets appear only on the parental side of a zone cut and are
authoritative data in the parent zone. As with any other
authoritative RRset, the DS RRset MUST be included in zone transfers
of the zone in which the RRset is authoritative data. In the case of
the DS RRset, this is the parent zone.

NSEC RRs appear in both the parent and child zones at a zone cut and
are authoritative data in both the parent and child zones. The
parental and child NSEC RRs at a zone cut are never identical to each
other, as the NSEC RR in the child zone's apex will always indicate
the presence of the child zone's SOA RR whereas the parental NSEC RR
at the zone cut will never indicate the presence of an SOA RR. As
with any other authoritative RRs, NSEC RRs MUST be included in zone
transfers of the zone in which they are authoritative data. The
parental NSEC RR at a zone cut MUST be included in zone transfers of
the parent zone, and the NSEC at the zone apex of the child zone MUST
be included in zone transfers of the child zone.

RRSIG RRs appear in both the parent and child zones at a zone cut and
are authoritative in whichever zone contains the authoritative RRset
for which the RRSIG RR provides the signature. That is, the RRSIG RR
for a DS RRset or a parental NSEC RR at a zone cut will be
authoritative in the parent zone, and the RRSIG for any RRset in the
child zone's apex will be authoritative in the child zone. Parental
and child RRSIG RRs at a zone cut will never be identical to each
other, as the Signer's Name field of an RRSIG RR in the child zone's
apex will indicate a DNSKEY RR in the child zone's apex whereas the
same field of a parental RRSIG RR at the zone cut will indicate a
DNSKEY RR in the parent zone's apex. As with any other authoritative
RRs, RRSIG RRs MUST be included in zone transfers of the zone in
which they are authoritative data.

#### The AD and CD Bits in an Authoritative Response

The CD and AD bits are designed for use in communication between
security-aware resolvers and security-aware recursive name servers.
These bits are for the most part not relevant to query processing by
security-aware authoritative name servers.

A security-aware name server does not perform signature validation
for authoritative data during query processing, even when the CD bit
is clear. A security-aware name server SHOULD clear the CD bit when
composing an authoritative response.

A security-aware name server MUST NOT set the AD bit in a response
unless the name server considers all RRsets in the Answer and
Authority sections of the response to be authentic. A security-aware
name server's local policy MAY consider data from an authoritative
zone to be authentic without further validation. However, the name
server MUST NOT do so unless the name server obtained the
authoritative zone via secure means (such as a secure zone transfer
mechanism) and MUST NOT do so unless this behavior has been
configured explicitly.

A security-aware name server that supports recursion MUST follow the
rules for the CD and AD bits given in [x.x.x] when generating a
response that involves data obtained via recursion.

### Recursive Name Servers

As explained in [x.x.x], a security-aware recursive name server is
an entity that acts in both the security-aware name server and
security-aware resolver roles. This section uses the terms "name
server side" and "resolver side" to refer to the code within a
security-aware recursive name server that implements the
security-aware name server role and the code that implements the
security-aware resolver role, respectively.

The resolver side follows the usual rules for caching and negative
caching that would apply to any security-aware resolver.

#### The DO Bit

The resolver side of a security-aware recursive name server MUST set
the DO bit when sending requests, regardless of the state of the DO
bit in the initiating request received by the name server side. If
the DO bit in an initiating query is not set, the name server side
MUST strip any authenticating DNSSEC RRs from the response but MUST
NOT strip any DNSSEC RR types that the initiating query explicitly
requested.

#### The CD Bit

The CD bit exists in order to allow a security-aware resolver to
disable signature validation in a security-aware name server's
processing of a particular query.

The name server side MUST copy the setting of the CD bit from a query
to the corresponding response.

The name server side of a security-aware recursive name server MUST
pass the state of the CD bit to the resolver side along with the rest
of an initiating query, so that the resolver side will know whether
it is required to verify the response data it returns to the name
server side. If the CD bit is set, it indicates that the originating
resolver is willing to perform whatever authentication its local
policy requires. Thus, the resolver side of the recursive name
server need not perform authentication on the RRsets in the response.
When the CD bit is set, the recursive name server SHOULD, if
possible, return the requested data to the originating resolver, even
if the recursive name server's local authentication policy would
reject the records in question. That is, by setting the CD bit, the
originating resolver has indicated that it takes responsibility for
performing its own authentication, and the recursive name server
should not interfere.

If the resolver side implements a BAD cache (see [x.x.x]) and the
name server side receives a query that matches an entry in the
resolver side's BAD cache, the name server side's response depends on
the state of the CD bit in the original query. If the CD bit is set,
the name server side SHOULD return the data from the BAD cache; if
the CD bit is not set, the name server side MUST return RCODE 2
(server failure).

The intent of the above rule is to provide the raw data to clients
that are capable of performing their own signature verification
checks while protecting clients that depend on the resolver side of a
security-aware recursive name server to perform such checks. Several
of the possible reasons why signature validation might fail involve
conditions that may not apply equally to the recursive name server
and the client that invoked it. For example, the recursive name
server's clock may be set incorrectly, or the client may have
knowledge of a relevant island of security that the recursive name
server does not share. In such cases, "protecting" a client that is
capable of performing its own signature validation from ever seeing
the "bad" data does not help the client.

#### The AD Bit

The name server side of a security-aware recursive name server MUST
NOT set the AD bit in a response unless the name server considers all
RRsets in the Answer and Authority sections of the response to be
authentic. The name server side SHOULD set the AD bit if and only if
the resolver side considers all RRsets in the Answer section and any
relevant negative response RRs in the Authority section to be
authentic. The resolver side MUST follow the procedure described in
Section 5 to determine whether the RRs in question are authentic.
However, for backward compatibility, a recursive name server MAY set
the AD bit when a response includes unsigned CNAME RRs if those CNAME
RRs demonstrably could have been synthesized from an authentic DNAME
RR that is also included in the response according to the synthesis
rules described in [x.x.x].

## Resolving

This section describes the behavior of entities that include
security-aware resolver functions. In many cases such functions will
be part of a security-aware recursive name server, but a stand-alone
security-aware resolver has many of the same requirements. Functions
specific to security-aware recursive name servers are described in
[x.x.x].

### EDNS Support

A security-aware resolver MUST include an EDNS OPT
pseudo-RR with the DO bit set when sending queries.

A security-aware resolver MUST support a message size of at least
1220 octets, SHOULD support a message size of 4000 octets, and MUST
use the "sender's UDP payload size" field in the EDNS OPT pseudo-RR
to advertise the message size that it is willing to accept. A
security-aware resolver's IP layer MUST handle fragmented UDP packets
correctly regardless of whether any such fragmented packets were
received via IPv4 or IPv6. Please see [RFC-1122](https://ietf.org/rfc/rfc1122.txt), [RFC-2460](https://ietf.org/rfc/rfc2460.txt), and
[RFC-3226](https://ietf.org/rfc/rfc3226.txt) for discussion of these requirements.

### Signature Verification Support

A security-aware resolver MUST support the signature verification
mechanisms described in [x.x.x] and SHOULD apply them to every
received response, except when:

*  the security-aware resolver is part of a security-aware recursive
    name server, and the response is the result of recursion on behalf
    of a query received with the CD bit set

*  the response is the result of a query generated directly via some
    form of application interface that instructed the security-aware
    resolver not to perform validation for this query

*  validation for this query has been disabled by local policy

A security-aware resolver's support for signature verification MUST
include support for verification of wildcard owner names.

Security-aware resolvers MAY query for missing security RRs in an
attempt to perform validation; implementations that choose to do so
must be aware that the answers received may not be sufficient to
validate the original response. For example, a zone update may have
changed (or deleted) the desired information between the original and
follow-up queries.

When attempting to retrieve missing NSEC RRs that reside on the
parental side at a zone cut, a security-aware iterative-mode resolver
MUST query the name servers for the parent zone, not the child zone.

When attempting to retrieve a missing DS, a security-aware
iterative-mode resolver MUST query the name servers for the parent
zone, not the child zone. As explained in [Responding to Queries for DS RRs],
security-aware name servers need to apply special processing rules to
handle the DS RR, and in some situations the resolver may also need
to apply special rules to locate the name servers for the parent zone
if the resolver does not already have the parent's NS RRset. To
locate the parent NS RRset, the resolver can start with the
delegation name, strip off the leftmost label, and query for an NS
RRset by that name. If no NS RRset is present at that name, the
resolver then strips off the leftmost remaining label and retries the
query for that name, repeating this process of walking up the tree
until it either finds the NS RRset or runs out of labels.

### Determining Security Status of Data

A security-aware resolver MUST be able to determine whether it should
expect a particular RRset to be signed. More precisely, a
security-aware resolver must be able to distinguish between four
cases:

   **Secure**: An RRset for which the resolver is able to build a chain of
      signed DNSKEY and DS RRs from a trusted security anchor to the
      RRset. In this case, the RRset should be signed and is subject to
      signature validation, as described above.

   **Insecure**: An RRset for which the resolver knows that it has no chain
      of signed DNSKEY and DS RRs from any trusted starting point to the
      RRset. This can occur when the target RRset lies in an unsigned
      zone or in a descendent of an unsigned zone. In this case, the
      RRset may or may not be signed, but the resolver will not be able
      to verify the signature.

   **Bogus**: An RRset for which the resolver believes that it ought to be
      able to establish a chain of trust but for which it is unable to
      do so, either due to signatures that for some reason fail to
      validate or due to missing data that the relevant DNSSEC RRs
      indicate should be present. This case may indicate an attack but
      may also indicate a configuration error or some form of data
      corruption.

   **Indeterminate**: An RRset for which the resolver is not able to
      determine whether the RRset should be signed, as the resolver is
      not able to obtain the necessary DNSSEC RRs. This can occur when
      the security-aware resolver is not able to contact security-aware
      name servers for the relevant zones.

### Configured Trust Anchors

A security-aware resolver MUST be capable of being configured with at
least one trusted public key or DS RR and SHOULD be capable of being
configured with multiple trusted public keys or DS RRs. Since a
security-aware resolver will not be able to validate signatures
without such a configured trust anchor, the resolver SHOULD have some
reasonably robust mechanism for obtaining such keys when it boots;
examples of such a mechanism would be some form of non-volatile
storage (such as a disk drive) or some form of trusted local network
configuration mechanism.

Note that trust anchors also cover key material that is updated in a
secure manner. This secure manner could be through physical media, a
key exchange protocol, or some other out-of-band means.

### Response Caching

A security-aware resolver SHOULD cache each response as a single
atomic entry containing the entire answer, including the named RRset
and any associated DNSSEC RRs. The resolver SHOULD discard the
entire atomic entry when any of the RRs contained in it expire. In
most cases the appropriate cache index for the atomic entry will be
the triple <QNAME, QTYPE, QCLASS>, but in cases such as the response
form described in [Including NSEC RRs: Name Error Response] the appropriate cache index will be
the double <QNAME,QCLASS>.

The reason for these recommendations is that, between the initial
query and the expiration of the data from the cache, the
authoritative data might have been changed (for example, via dynamic
update).

There are two situations for which this is relevant:

1. By using the RRSIG record, it is possible to deduce that an
    answer was synthesized from a wildcard. A security-aware
    recursive name server could store this wildcard data and use it
    to generate positive responses to queries other than the name for
    which the original answer was first received.

2. NSEC RRs received to prove the non-existence of a name could be
    reused by a security-aware resolver to prove the non-existence of
    any name in the name range it spans.

In theory, a resolver could use wildcards or NSEC RRs to generate
positive and negative responses (respectively) until the TTL or
signatures on the records in question expire. However, it seems
prudent for resolvers to avoid blocking new authoritative data or
synthesizing new data on their own. Resolvers that follow this
recommendation will have a more consistent view of the namespace.

### Handling of the CD and AD Bits

A security-aware resolver MAY set a query's CD bit in order to
indicate that the resolver takes responsibility for performing
whatever authentication its local policy requires on the RRsets in
the response. See [Recursive Name Servers] for the effect this bit has on the
behavior of security-aware recursive name servers.

A security-aware resolver MUST clear the AD bit when composing query
messages to protect against buggy name servers that blindly copy
header bits that they do not understand from the query message to the
response message.

A resolver MUST disregard the meaning of the CD and AD bits in a
response unless the response was obtained by using a secure channel
or the resolver was specifically configured to regard the message
header bits without using a secure channel.

### Caching BAD Data

While many validation errors will be transient, some are likely to be
more persistent, such as those caused by administrative error
(failure to re-sign a zone, clock skew, and so forth). Since
requerying will not help in these cases, validating resolvers might
generate a significant amount of unnecessary DNS traffic as a result
of repeated queries for RRsets with persistent validation failures.

To prevent such unnecessary DNS traffic, security-aware resolvers MAY
cache data with invalid signatures, with some restrictions.

Conceptually, caching such data is similar to negative caching,
except that instead of caching a valid negative
response, the resolver is caching the fact that a particular answer
failed to validate. This document refers to a cache of data with
invalid signatures as a "BAD cache".

Resolvers that implement a BAD cache MUST take steps to prevent the
cache from being useful as a denial-of-service attack amplifier,
particularly the following:

*  Since RRsets that fail to validate do not have trustworthy TTLs,
    the implementation MUST assign a TTL. This TTL SHOULD be small,
    in order to mitigate the effect of caching the results of an
    attack.

*  In order to prevent caching of a transient validation failure
    (which might be the result of an attack), resolvers SHOULD track
    queries that result in validation failures and SHOULD only answer
    from the BAD cache after the number of times that responses to
    queries for that particular <QNAME, QTYPE, QCLASS> have failed to
    validate exceeds a threshold value.

Resolvers MUST NOT return RRsets from the BAD cache unless the
resolver is not required to validate the signatures of the RRsets in
question under the rules given in [Signature Verification Support]. See
[The CD Bit] for discussion of how the responses returned by a
security-aware recursive name server interact with a BAD cache.

### Synthesized CNAMEs

A validating security-aware resolver MUST treat the signature of a
valid signed DNAME RR as also covering unsigned CNAME RRs that could
have been synthesized from the DNAME RR, as described in [x.x.x],
at least to the extent of not rejecting a response message solely
because it contains such CNAME RRs. The resolver MAY retain such
CNAME RRs in its cache or in the answers it hands back, but is not
required to do so.

### Stub Resolvers

A security-aware stub resolver MUST support the DNSSEC RR types, at
least to the extent of not mishandling responses just because they
contain DNSSEC RRs.

#### Handling of the DO Bit

A non-validating security-aware stub resolver MAY include the DNSSEC
RRs returned by a security-aware recursive name server as part of the
data that the stub resolver hands back to the application that
invoked it, but is not required to do so. A non-validating stub
resolver that seeks to do this will need to set the DO bit in order
to receive DNSSEC RRs from the recursive name server.

A validating security-aware stub resolver MUST set the DO bit,
because otherwise it will not receive the DNSSEC RRs it needs to
perform signature validation.

#### Handling of the CD Bit

A non-validating security-aware stub resolver SHOULD NOT set the CD
bit when sending queries unless it is requested by the application
layer, as by definition, a non-validating stub resolver depends on
the security-aware recursive name server to perform validation on its
behalf.

A validating security-aware stub resolver SHOULD set the CD bit,
because otherwise the security-aware recursive name server will
answer the query using the name server's local policy, which may
prevent the stub resolver from receiving data that would be
acceptable to the stub resolver's local policy.

#### Handling of the AD Bit

A non-validating security-aware stub resolver MAY chose to examine
the setting of the AD bit in response messages that it receives in
order to determine whether the security-aware recursive name server
that sent the response claims to have cryptographically verified the
data in the Answer and Authority sections of the response message.
Note, however, that the responses received by a security-aware stub
resolver are heavily dependent on the local policy of the
security-aware recursive name server. Therefore, there may be little
practical value in checking the status of the AD bit, except perhaps
as a debugging aid. In any case, a security-aware stub resolver MUST
NOT place any reliance on signature validation allegedly performed on
its behalf, except when the security-aware stub resolver obtained the
data in question from a trusted security-aware recursive name server
via a secure channel.

A validating security-aware stub resolver SHOULD NOT examine the
setting of the AD bit in response messages, as, by definition, the
stub resolver performs its own signature validation regardless of the
setting of the AD bit.

## Authenticating DNS Responses


To use DNSSEC RRs for authentication, a security-aware resolver
requires configured knowledge of at least one authenticated DNSKEY or
DS RR. The process for obtaining and authenticating this initial
"trust anchor" is achieved via some external mechanism. For example, a
resolver could use some off-line authenticated exchange to obtain a
zone's DNSKEY RR or to obtain a DS RR that identifies and
authenticates a zone's DNSKEY RR. The remainder of this section
assumes that the resolver has somehow obtained an initial set of
trust anchors.

An initial DNSKEY RR can be used to authenticate a zone's apex DNSKEY
RRset. To authenticate an apex DNSKEY RRset by using an initial key,
the resolver MUST:

1. verify that the initial DNSKEY RR appears in the apex DNSKEY
    RRset, and that the DNSKEY RR has the Zone Key Flag (DNSKEY RDATA
    bit 7) set; and

2. verify that there is some RRSIG RR that covers the apex DNSKEY
    RRset, and that the combination of the RRSIG RR and the initial
    DNSKEY RR authenticates the DNSKEY RRset. The process for using
    an RRSIG RR to authenticate an RRset is described in [x.x.x].

Once the resolver has authenticated the apex DNSKEY RRset by using an
initial DNSKEY RR, delegations from that zone can be authenticated by
using DS RRs. This allows a resolver to start from an initial key
and use DS RRsets to proceed recursively down the DNS tree, obtaining
other apex DNSKEY RRsets. If the resolver were configured with a
root DNSKEY RR, and if every delegation had a DS RR associated with
it, then the resolver could obtain and validate any apex DNSKEY
RRset. The process of using DS RRs to authenticate referrals is
described in [Authenticating Referrals].

[x.x.x] shows how the resolver can use DNSKEY RRs in the apex
DNSKEY RRset and RRSIG RRs from the zone to authenticate any other
RRsets in the zone once the resolver has authenticated a zone's apex
DNSKEY RRset. [x.x.x] shows how the resolver can use
authenticated NSEC RRsets from the zone to prove that an RRset is not
present in the zone.

When a resolver indicates support for DNSSEC (by setting the DO bit),
a security-aware name server should attempt to provide the necessary
DNSKEY, RRSIG, NSEC, and DS RRsets in a response (see [x.x.x]).
However, a security-aware resolver may still receive a response that
lacks the appropriate DNSSEC RRs, whether due to configuration issues
such as an upstream security-oblivious recursive name server that
accidentally interferes with DNSSEC RRs or due to a deliberate attack
in which an adversary forges a response, strips DNSSEC RRs from a
response, or modifies a query so that DNSSEC RRs appear not to be
requested. The absence of DNSSEC data in a response MUST NOT by
itself be taken as an indication that no authentication information
exists.

A resolver SHOULD expect authentication information from signed
zones. A resolver SHOULD believe that a zone is signed if the
resolver has been configured with public key information for the
zone, or if the zone's parent is signed and the delegation from the
parent contains a DS RRset.

### Special Considerations for Islands of Security

Islands of security are signed zones for which it is
not possible to construct an authentication chain to the zone from
its parent. Validating signatures within an island of security
requires that the validator have some other means of obtaining an
initial authenticated zone key for the island. If a validator cannot
obtain such a key, it SHOULD switch to operating as if the zones in
the island of security are unsigned.

All the normal processes for validating responses apply to islands of
security. The only difference between normal validation and
validation within an island of security is in how the validator
obtains a trust anchor for the authentication chain.

### Authenticating Referrals

Once the apex DNSKEY RRset for a signed parent zone has been
authenticated, DS RRsets can be used to authenticate the delegation
to a signed child zone. A DS RR identifies a DNSKEY RR in the child
zone's apex DNSKEY RRset and contains a cryptographic digest of the
child zone's DNSKEY RR. Use of a strong cryptographic digest
algorithm ensures that it is computationally infeasible for an
adversary to generate a DNSKEY RR that matches the digest. Thus,
authenticating the digest allows a resolver to authenticate the
matching DNSKEY RR. The resolver can then use this child DNSKEY RR
to authenticate the entire child apex DNSKEY RRset.

Given a DS RR for a delegation, the child zone's apex DNSKEY RRset
can be authenticated if all of the following hold:

*  The DS RR has been authenticated using some DNSKEY RR in the
    parent's apex DNSKEY RRset (see [x.x.x]).

*  The Algorithm and Key Tag in the DS RR match the Algorithm field
    and the key tag of a DNSKEY RR in the child zone's apex DNSKEY
    RRset, and, when the DNSKEY RR's owner name and RDATA are hashed
    using the digest algorithm specified in the DS RR's Digest Type
    field, the resulting digest value matches the Digest field of the
    DS RR.

*  The matching DNSKEY RR in the child zone has the Zone Flag bit
    set, the corresponding private key has signed the child zone's
    apex DNSKEY RRset, and the resulting RRSIG RR authenticates the
    child zone's apex DNSKEY RRset.

If the referral from the parent zone did not contain a DS RRset, the
response should have included a signed NSEC RRset proving that no DS
RRset exists for the delegated name (see [x.x.x]). A
security-aware resolver MUST query the name servers for the parent
zone for the DS RRset if the referral includes neither a DS RRset nor
a NSEC RRset proving that the DS RRset does not exist (see [x.x.x]).

If the validator authenticates an NSEC RRset that proves that no DS
RRset is present for this zone, then there is no authentication path
leading from the parent to the child. If the resolver has an initial
DNSKEY or DS RR that belongs to the child zone or to any delegation
below the child zone, this initial DNSKEY or DS RR MAY be used to
re-establish an authentication path. If no such initial DNSKEY or DS
RR exists, the validator cannot authenticate RRsets in or below the
child zone.

If the validator does not support any of the algorithms listed in an
authenticated DS RRset, then the resolver has no supported
authentication path leading from the parent to the child. The
resolver should treat this case as it would the case of an
authenticated NSEC RRset proving that no DS RRset exists, as
described above.

Note that, for a signed delegation, there are two NSEC RRs associated
with the delegated name. One NSEC RR resides in the parent zone and
can be used to prove whether a DS RRset exists for the delegated
name. The second NSEC RR resides in the child zone and identifies
which RRsets are present at the apex of the child zone. The parent
NSEC RR and child NSEC RR can always be distinguished because the SOA
bit will be set in the child NSEC RR and clear in the parent NSEC RR.
A security-aware resolver MUST use the parent NSEC RR when attempting
to prove that a DS RRset does not exist.

If the resolver does not support any of the algorithms listed in an
authenticated DS RRset, then the resolver will not be able to verify
the authentication path to the child zone. In this case, the
resolver SHOULD treat the child zone as if it were unsigned.


# Glossary
