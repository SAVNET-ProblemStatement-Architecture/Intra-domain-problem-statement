---
title: Source Address Validation in Intra-domain Networks Gap Analysis, Problem Statement, and Requirements
abbrev: Intra-domain SAVNET Problem Statement
docname: draft-ietf-savnet-intra-domain-problem-statement-23
obsoletes:
updates:
date:
category: info
submissionType: IETF

ipr: trust200902
area: Routing
workgroup: SAVNET
keyword: SAV

author:
 -
  ins: D. Li
  name: Dan Li
  organization: Tsinghua University
  email: tolidan@tsinghua.edu.cn
  city: Beijing
  country: China
 -
  ins: J. Wu
  name: Jianping Wu
  organization: Tsinghua University
  email: jianping@cernet.edu.cn
  city: Beijing
  country: China
 -
  ins: L. Qin
  name: Lancheng Qin
  organization: Zhongguancun Laboratory
  email: qinlc@mail.zgclab.edu.cn
  city: Beijing
  country: China
 -
  ins: M. Huang
  name: Mingqing Huang
  organization: Zhongguancun Laboratory
  email: huangmq@mail.zgclab.edu.cn
  city: Beijing
  country: China
 -
  ins: N. Geng
  name: Nan Geng
  organization: Huawei
  email: gengnan@huawei.com
  city: Beijing
  country: China

normative:
  RFC2827:
  RFC3704:
  RFC5210:
  RFC8704:
  RFC7513:
informative:
  cable-verify:
    title: Cable Source-Verify and IP Address Security
    author: 
    org: Cisco
    date: 2021-01
    target: https://www.cisco.com/c/en/us/support/docs/broadband-cable/cable-security/20691-source-verify.html
  IPSG:
    title: Configuring DHCP Features and IP Source Guard
    author: 
    org: Cisco
    date: 2016-01
    target: https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960/software/release/12-2_53_se/configuration/guide/2960scg/swdhcp82.html
  CAIDA-spoofer:
    title: State of IP Spoofing
    author: 
    org: CAIDA
    date: 
    target: https://spoofer.caida.org/summary.php?
  RFC6890:

  
...

--- abstract

Source address validation (SAV) is an important means to mitigate IP source address spoofing [RFC2827]. This document analyzes the gaps in current operational mechanisms for intra-domain SAV. It also identifies the properties that new intra-domain SAV mechanisms are expected to provide.

--- middle

# Introduction {#sec-intro}

Source Address Validation (SAV) defends against source address spoofing. Network operators can enforce SAV at the following levels (see [RFC5210]):

* IP source address validation in the access network

* IP source address validation at intra-AS/ingress point

* IP source address validation in the inter-AS Case (neighboring AS) 

Some access networks have already deployed SAV mechanisms. These mechanisms are typically deployed on switches in the access network and aim to prevent each host connected to them from using the source address of another host on the Internet [RFC5210]. Mechanisms include:

* Source Address Validation Improvement (SAVI) Solution for DHCP [RFC7513]

* IP Source Guard (IPSG) based on DHCP snooping [IPSG]

* Cable Source-Verify [cable-verify] 

However, access-network SAV mechanisms are not universally deployed [CAIDA-spoofer]. Therefore, intra-domain (i.e., intra-AS) SAV and inter-domain (i.e., inter-AS) SAV are required [RFC5210].

In this document, intra-domain SAV refers to SAV at a domain's external interfaces that do not carry external BGP (eBGP) sessions (i.e., non-BGP external interfaces). SAV at internal interfaces between routers within the same domain is outside the scope of this document. SAV at BGP-facing external interfaces is classified as inter-domain SAV. For a domain, as illustrated in {{intra-domain}}, a non-BGP external interface may connect to a set of hosts, a non-BGP customer network, or a non-BGP Internet Service Provider (ISP) network. Intra-domain SAV validates source addresses of data traffic received at such interfaces.

~~~
      +-----------------+         +---------------+ 
      |   Non-BGP ISP   |         | eBGP Neighbor |
      +-----------------+         +---------------+ 
              |                           |           
              |                           |           
              |                           |
+-------------|---------------------------|---------+ 
|Domain       \/                          |         | 
|         +---#------+               +----------+   | 
|         | Router 3 +---------------+ Router 4 |   | 
|         +----------+               +----------+   | 
|          /        \                     |         | 
|         /          \                    |         | 
|        /            \                   |         | 
| +----------+     +----------+      +----------+   | 
| | Router 1 |     | Router 2 +------+ Router 5 |   | 
| +------*---+     +--*-------+      +----X-----+   | 
|        /\           /\                  /\        | 
|         \           /                   |         | 
+----------\---------/--------------------|---------+ 
       +----------------+         +---------------+  
       |Non-BGP Customer|         |   A Set of    |  
       |   Network      |         |     Hosts     |  
       |     (P1)       |         |     (P2)      |  
       +----------------+         +---------------+ 
                                                    
  This document focuses on SAV at a domain's non-BGP 
  external interfaces including Interfaces  'X', '*', and '#'.
~~~
{: #intra-domain  title="Deployment locations of intra-domain SAV"}

This document analyzes the gaps in current operational mechanisms for intra-domain SAV. It also identifies the properties that new intra-domain SAV mechanisms are expected to provide.

## Terminology

Non-BGP Customer Network: A stub network (i.e., a network that only originates traffic) connected to its provider network for Internet connectivity and does not participate in eBGP peering with its provider network.

Non-BGP Internet Service Provider (ISP) Network: A network that forwards traffic from its customer network to the Internet and does not participate in eBGP peering with its customer network.

SAV Rule: The rule in a router that describes the mapping relationship between a source address (prefix) and the valid incoming interface(s). It is used by a router to make SAV decisions.

Improper Block: The validation results that the packets with legitimate source addresses are blocked improperly due to inaccurate SAV rules.

Improper Permit: The validation results that the packets with spoofed source addresses are permitted improperly due to inaccurate SAV rules.

Proper Block: The validation results that packets with spoofed source addresses are blocked by SAV rules.

Proper Permit: The validation results that packets with legitimate source addresses are permitted by SAV rules.

SAV-specific Information: The information specialized for SAV rule generation.

Direct Server Return (DSR): A traffic delivery model commonly used by Content Delivery Networks (CDNs) that use anycast service addresses while delivering data from edge locations that do not announce those addresses. In such deployments, a request is received by the anycast server or location, but the response is sent directly by another server (i.e., the edge location) with the anycast service address as the source address, rather than the address used to reach the edge server. This can create a legitimate hidden-prefix scenario.

## Requirements Language

{::boilerplate bcp14-tagged}

The requirements language is used in {{sec-requirement}} and applies to implementations of SAV conformant to the listed requirements.

# Issues with Current Operational Intra-domain SAV Mechanisms {#sec-mechanisms}

Although BCP 38 [RFC2827] and BCP 84 [RFC3704] specify several ingress filtering methods primarily intended for inter-domain SAV, some of these methods have also been applied to intra-domain SAV in operational practice. This section summarizes the problems of mechanisms currently used to implement intra-domain SAV. These mechanisms have significant limitations in terms of automated updates or accurate validation.

- Access Control Lists (ACLs) can be used as SAV filters [RFC2827] to check whether the source address of a packet matches a set of permitted or prohibited prefixes. When applied on a router interface, each ACL entry (ACE) used for SAV filtering specifies both matching conditions (i.e., prefixes) and the corresponding action (e.g., permit or deny), and packets are processed accordingly. To ensure correct filtering behavior, the ACLs used for SAV filtering need to be updated when the permitted or prohibited prefixes change; otherwise, packets may be improperly permitted or blocked. In ACL-based ingress filtering [RFC2827] deployments, keeping these ACLs up to date can introduce operational challenges when operators need to detect prefix changes and determine and apply the corresponding ACL updates.

- Strict uRPF [RFC3704] provides an automated SAV filter by validating the source address of each packet against the router’s local Forwarding Information Base (FIB). A packet is accepted only if (i) the FIB contains a prefix covering the source address, and (ii) the FIB entry’s outgoing interface matches the packet’s incoming interface. Otherwise, the packet is discarded. It may block legitimate traffic in the asymmetric routing or hidden prefix scenarios (see {{subsec-ar}} and {{subsec-hp}}). Strict uRPF may mistakenly consider a valid incoming interface as invalid, resulting in legitimate packets being blocked (i.e., an improper block problem).

- Loose uRPF [RFC3704] also relies on the local FIB for validation, but only checks for the presence of a covering prefix. A packet is accepted if the FIB contains a prefix that covers the source address, regardless of the incoming interface. Since its rules are overly permissive, any spoofed packet with a source address present in the FIB may be permitted by loose uRPF (i.e., an improper permit problem). 

- Enhanced Feasible Path uRPF (EFP-uRPF) [RFC8704] is an advanced SAV mechanism specifically designed for inter-domain SAV. It enforces SAV on eBGP interfaces facing a customer AS by leveraging BGP data received from external ASes. EFP-uRPF is not analyzed in this document, as it is outside the scope of intra-domain SAV.

# Gap Analysis {#sec-gap}

This section analyzes the gaps and key challenges of the current operational intra-domain SAV mechanisms.

ACL-based SAV can be deployed on interfaces facing a non-BGP customer network or a set of hosts, permitting only packets with authorized source addresses. Such mechanism can also be applied on interfaces facing a non-BGP ISP network to block packets with prohibited source addresses, including internal-use-only addresses, unallocated addresses, and addresses single-homed to the local domain (e.g., P1 and P2 in {{intra-domain}}). A key limitation of ACL-based SAV is the need to maintain consistency between SAV state and ACL rules. Operators need to update ACL rules to reflect changes in prefixes or topology, and delays or inconsistencies in this process may result in outdated rules that inadvertently block legitimate traffic or permit spoofed traffic.

Loose uRPF sacrifices directionality, so its effectiveness in mitigating source address spoofing is very limited, and improper permit problems may occur. With strict uRPF, it may drop legitimate packets in scenarios such as asymmetric routing or hidden prefixes. 

The following subsections describe two specific gap scenarios for intra-domain SAV.

## Asymmetric Routing Scenario {#subsec-ar}

Asymmetric routing means a packet traverses from a source to a destination in one path and takes a different path when it returns to the source. Asymmetric routing can occur within an AS due to routing policy, traffic engineering, etc. 

For example, a non-BGP customer network connected to multiple routers of the AS may need to perform load balancing on incoming traffic, thereby resulting in asymmetric routing. {{multi-home}} illustrates an example of asymmetric routing. The non-BGP customer network owns prefix 2001:db8::/55 and connects to two routers of the AS, Router 1 and Router 2. Router 1, Router 2, and Router 3 exchange routing information via the intra-domain routing protocol. To achieve load balancing for inbound traffic, the non-BGP customer network expects traffic destined for 2001:db8:0::/56 to enter through Router 1, and traffic destined for 2001:db8:0:100::/56 to enter through Router 2. To this end, Router 1 advertises 2001:db8:0::/56 and Router 2 advertises 2001:db8:0:100::/56 through the intra-domain routing protocol. {{multi-home}} also shows the corresponding FIB entries of Router 1 and Router 2 for the two prefixes.

~~~
 +----------------------------------------------------------+
 |Domain                                                    |
 |                      +----------+                        |
 |                      | Router 3 |                        |
 |                      +----------+                        |
 |                       /       \                          |
 |                      /         \                         |
 |                     /           \                        |
 |            +----------+       +----------+               |
 |            | Router 1 |       | Router 2 |               |
 |            +-----*----+       +----------+               |
 |                  /\               /                      |
 |                   \              /                       |
 +--------------------\------------/------------------------+
  Traffic with         \          / Traffic with            
  source IP addresses   \        /  destination IP addresses
  of 2001:db8:0:100::/56 \      \/  of 2001:db8:0:100::/56  
                    +----------------+                     
                    |Non-BGP Customer|                     
                    |    Network     |                     
                    |(2001:db8::/55) |                     
                    +----------------+                     

 FIB of Router 1                FIB of Router 2
 Dest                Next_hop   Dest                Next_hop
 2001:db8:0::/56     Non-BGP    2001:db8:0:100::/56 Non-BGP
                     Customer                       Customer
                     Nestwork                       Network
 2001:db8:0:100::/56 Router 3   2001:db8:0::/56     Router 3

 The legitimate traffic originated from non-BGP customer network 
 with source addresses in 2001:db8:0:100::/56 will be improperly 
 blocked by strict uRPF on Router 1.
~~~
{: #multi-home title="An example of asymmetric routing"}

Although the non-BGP customer network does not expect to receive inbound traffic for 2001:db8:0:100::/56 via Router 1, it can send outbound traffic with source addresses in that prefix through Router 1. As a result, data packets between the non-BGP customer network and Router 1 may follow asymmetric paths. Arrows in the figure indicate the direction of traffic flow.

If Router 1 enforces strict uRPF by checking the FIB entry for the prefix 2001:db8:0:100::/56, the corresponding SAV rule would only allow packets with a source address from 2001:db8:0:100::/56 that arrive via Router 3. Consequently, when the non-BGP customer network sends packets with a source address in 2001:db8:0:100::/56 to Router 1, strict uRPF would incorrectly drop these legitimate packets. Similarly, if Router 2 enforces strict uRPF, it would incorrectly block legitimate packets from the non-BGP customer network that use source addresses within the prefix 2001:db8:0::/56.

If Router 1 and Router 2 enforce loose uRPF, they would not improperly block legitimate packets from the non-BGP customer, but would improperly permit spoofed packets using source addresses covered in their FIBs, as discussed in {{sec-mechanisms}}.

## Hidden Prefix Scenario {#subsec-hp}

The intra-domain hidden prefix scenario refers to situations in which a host or non-BGP customer legitimately originates traffic using source addresses that are not visible to the intra-domain routing protocol within the domain.

- A host (for example, a cloud server instance operated by a tenant) may originate traffic using a source address not allocated by the AS operator. This can occur in deployments such as Direct Server Return (DSR), where return traffic is sent directly from the server using a service IP address that is not part of the operator’s internal routing view.

- A non-BGP customer network may originate traffic using source addresses that are not advertised to the domain operator. This can occur in scenarios such as Direct Server Return (DSR) deployments or when the customer network uses address space assigned by another provider (e.g., in multi-homing or hybrid connectivity scenarios), and such prefixes are not propagated within the operator’s intra-domain routing system.

For ACL-based SAV, enforcing correct filtering in these scenarios requires authoritative information that explicitly specifies which source addresses the host or non-BGP customer is authorized to use. In practice, such authoritative information is often missing. Strict uRPF and Loose uRPF also fail in hidden prefix scenarios. They will drop packets from hidden prefixes because the source addresses are absent from the router's FIB or are received from unexpected interfaces.

# Requirements for New SAV Mechanisms {#sec-requirement}

This section identifies five requirements for new intra-domain SAV mechanisms. These requirements describe the properties that such mechanisms are expected to provide in order to improve upon existing mechanisms, but do not make assumptions about how those properties are achieved. They do not mandate or justify any specific extension to routing or other protocols and therefore cannot be used to directly initiate standards-track protocol changes.

Existing intra-domain SAV mechanisms have important limitations. Current uRPF-based mechanisms derive SAV decisions from routing or forwarding state, which is intended to express reachability rather than authorization of source address usage. More generally, current mechanisms lack authoritative information specifically intended for source address validation that can be consistently and automatically consumed by SAV mechanisms. As a result, uRPF-based mechanisms may not provide accurate validation in scenarios such as asymmetric routing or hidden prefixes ({{sec-gap}}). Existing ACL-based ingress filtering, by contrast, rely on operator-driven ACL maintenance, which can limit their applicability in dynamic environments. These limitations motivate the requirements described in this section.

## Accurate Validation {#sub-require1}

Any new intra-domain SAV mechanism MUST improve the accuracy of source address validation compared to existing uRPF-based mechanisms. In particular, it MUST reduce the occurrence of improper blocks (i.e., blocking legitimate traffic), improper permits (i.e., allowing spoofed traffic), or both. Specifically, it MUST satisfy the following conditions:

- result in fewer improper blocks than strict uRPF, particularly in scenarios involving asymmetric routes or hidden prefixes;
- result in fewer improper permits than loose uRPF.

To achieve higher SAV accuracy, additional information beyond the local FIB (e.g., SAV-specific information) may be needed to make validation decisions. By integrating such information, routers may have the ability to account for asymmetric routes and hidden prefixes, resulting in more accurate SAV rules.

## Automatic Updates

Any new intra-domain SAV mechanism MUST be capable of automatically collecting and processing relevant information, and using it to derive and update SAV state and corresponding filtering rules on routers. Automation helps reduce operational complexity and maintenance overhead, while allowing some initial configuration to improve SAV accuracy. This ensures the mechanism is deployable in practical networks without introducing excessive management burden.

## Incremental Deployment Support

Any new intra-domain SAV mechanism MUST support incremental deployment and provide measurable benefits even when only a subset of external non-BGP interfaces deploy the mechanism.

## Fast Convergence

If any new intra-domain SAV mechanism requires disseminating SAV-specific information among intra-domain routers via a protocol, two considerations are essential. First, such mechanism MUST allow routers to learn updated SAV-specific information in a timely manner. Second, such mechanism MUST NOT transmit excessive SAV-specific information via a protocol, as this could significantly increase the burden on the routers’ control planes and potentially degrade the performance of existing protocols.

## Authentication of Information Used for SAV

Any new intra-domain SAV mechanism MUST use information that is authenticated or trusted, either through verification of its integrity and authenticity, or via an established trust relationship with the information source. If a SAV mechanism introduces new SAV-specific information, such information MUST be authenticated to ensure its integrity and authenticity before being used for SAV decision making.


# Security Considerations {#sec-security} 

This document discusses the limitations of existing intra-domain SAV practices and identifies problems and informational requirements for improved intra-domain SAV mechanisms. It does not specify new protocols or mechanisms and, as such, does not introduce any new security considerations.

# IANA Considerations {#sec-iana}

This document does not request any IANA allocations.

# Acknowledgements

Many thanks to the valuable comments from: Jared Mauch, Joel Halpern, Aijun Wang, Michael Richardson, Gert Doering, Libin Liu, Li Chen, Tony Przygienda, Yingzhen Qu, James Guichard, Linda Dunbar, Robert Sparks, Stephen Farrel, Ron Bonica, Xueyan Song, etc. We also thank the IETF Directorates and the IESG for their reviews and comments, which helped improve the clarity of this document.

--- back



