---
title: Source Address Validation in Intra-domain Networks Gap Analysis, Problem Statement, and Requirements
abbrev: Intra-domain SAVNET Problem Statement
docname: draft-ietf-savnet-intra-domain-problem-statement-22
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

informative:
  RFC2827:
  RFC3704:
  RFC5210:
  RFC8704:
  RFC7513:
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
  RFC6890:

  
...

--- abstract

This document provides a gap analysis of existing intra-domain source address validation mechanisms, describes the fundamental problems, and defines the basic requirements for technical improvements.

--- middle

# Introduction {#sec-intro}

Source Address Validation (SAV) defends against source address spoofing. Network operators can enforce SAV at the following levels (see [RFC5210]):

* Within the access network

* Within the domain (i.e., the autonomous system)

* Between domains (i.e., the autonomous systems)

Access networks have already deployed SAV mechanisms. These mechanisms typically are deployed on switches and prevent hosts from using the source address of another host on the Internet. Mechanisms include:

* Source Address Validation Improvement (SAVI) Solution for DHCP [RFC7513]

* IP Source Guard (IPSG) based on DHCP snooping [IPSG]

* Cable Source-Verify [cable-verify] 

However, access-network SAV mechanisms are not universally deployed. Therefore, intra-domain (i.e., intra-AS) SAV or/and inter-domain (i.e., inter-AS) SAV are required.

This document provides a gap analysis of the current operational intra-domain SAV mechanisms, identifies key problems to solve, and proposes basic requirements for any new intra-domain SAV solutions.

In this document, intra-domain SAV refers to SAV at external interfaces that do not carry external BGP (eBGP) sessions (i.e., external non-BGP interfaces). SAV at internal interfaces or eBGP interfaces is considered out of scope. Within a domain, as illustrated in {{intra-domain}}, an external non-BGP interface may connect to a set of hosts, a non-BGP customer network, or a non-BGP Internet Service Provider (ISP) network. The goal of intra-domain SAV at such interfaces is to prevent traffic using unauthorized source addresses from entering the domain.

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
                                                    
  External non-BGP interfaces include Interfaces
  'X', '*', and '#'.
~~~
{: #intra-domain  title="Deployment locations of intra-domain SAV"}

## Terminology

Non-BGP Customer Network: A stub network (i.e., a network that only originates traffic) connected to the local domain for Internet connectivity and does not participate in eBGP peering with the local domain.

Non-BGP Internet Service Provider (ISP) Network: A network that forwards traffic from the local domain to the Internet and does not participate in eBGP peering with the local domain.

SAV Rule: The rule in a router that describes the mapping relationship between a source address (prefix) and the valid incoming interface(s). It is used by a router to make SAV decisions.

Improper Block: The validation results that the packets with legitimate source addresses are blocked improperly due to inaccurate SAV rules.

Improper Permit: The validation results that the packets with spoofed source addresses are permitted improperly due to inaccurate SAV rules.

SAV-specific Information: The information specialized for SAV rule generation.

## Requirements Language

{::boilerplate bcp14-tagged}

# Current Operational Intra-domain SAV Mechanisms {#sec-mechanisms}

Although BCP 38 [RFC2827] and BCP 84 [RFC3704] specify several ingress filtering methods primarily intended for inter-domain SAV, some of these methods have also been applied to intra-domain SAV in operational practice. This section describes the mechanisms currently used to implement intra-domain SAV.

- Access Control Lists (ACLs) can be used as SAV filters [RFC2827] to check the source address of each packet against a set of permitted or prohibited prefixes. When applied on a router interface, packets that do not match the ACL entries are blocked. Since ACLs are configured and updated manually, timely updates are essential whenever the set of permitted or prohibited prefixes changes.

- Strict uRPF [RFC3704] provides an automated SAV filter by validating the source address of each packet against the router’s local Forwarding Information Base (FIB). A packet is accepted only if (i) the FIB contains a prefix covering the source address, and (ii) the FIB entry’s outgoing interface matches the packet’s incoming interface. Otherwise, the packet is discarded. Strict uRPF is commonly used to block spoofed packets originating from a directly connected host or non-BGP customer network.

- Loose uRPF [RFC3704] also relies on the local FIB for validation, but only checks for the presence of a covering prefix. A packet is accepted if the FIB contains a prefix that covers the source address, regardless of the incoming interface. 

- Enhanced Feasible Path uRPF (EFP-uRPF) [RFC8704] is an advanced SAV mechanism specifically designed for inter-domain SAV. It enforces SAV on eBGP interfaces facing a customer AS by leveraging BGP data received from external ASes. EFP-uRPF is not analyzed in this document, as it is outside the scope of intra-domain SAV.

# Gap Analysis {#sec-gap}

This section analyzes the gaps and key challenges of the current operational intra-domain SAV mechanisms.

ACL-based SAV can be deployed on interfaces facing a non-BGP customer network or a set of hosts, permitting only packets with authorized source addresses. Such mechanism can also be applied on interfaces facing a non-BGP ISP network to block packets with prohibited source addresses, including internal-use-only addresses, unallocated addresses, and addresses single-homed to the local domain (e.g., P1 and P2 in {{intra-domain}}). The main drawback of ACL-based SAV is that it requires manual maintenance. Operators must update them promptly to reflect changes in prefixes or topology. Failure to do so may result in outdated ACLs that inadvertently block legitimate traffic.

As noted in Section 2.4 of [RFC3704], loose uRPF sacrifices directionality, so its effectiveness in mitigating source address spoofing is very limited, and improper permit problems may occur. 

With strict uRPF, it may drop legitimate packets in scenarios such as asymmetric routing or hidden prefixes. The following subsections describe two specific gap scenarios that arise when using strict uRPF for intra-domain SAV.

## Asymmetric Routing Scenario

Asymmetric routing means a packet traverses from a source to a destination in one path and takes a different path when it returns to the source. Asymmetric routing can occur within an AS due to routing policy, traffic engineering, etc. For example, a non-BGP customer network connected to multiple routers of the AS may need to perform load balancing on incoming traffic, thereby resulting in asymmetric routing.

{{multi-home}} illustrates an example of asymmetric routing. The non-BGP customer network owns prefix 2001:db8::/55 [RFC6890] and connects to two routers of the AS, Router 1 and Router 2. Router 1, Router 2, and Router 3 exchange routing information via the intra-domain routing protocol. To achieve load balancing for inbound traffic, the non-BGP customer network expects traffic destined for 2001:db8:0::/56 to enter through Router 1, and traffic destined for 2001:db8:0:100::/56 to enter through Router 2. To this end, Router 1 advertises 2001:db8:0::/56 and Router 2 advertises 2001:db8:0:100::/56 through the intra-domain routing protocol. {{multi-home}} also shows the corresponding FIB entries of Router 1 and Router 2 for the two prefixes.

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

## Hidden Prefix Scenario

The intra-domain hidden prefix scenario refers to two situations in which a host or non-BGP customer legitimately originates traffic using source addresses that are not visible to the intra-domain routing protocol:

- A host (for example, a cloud server instance operated by a tenant) that originates traffic with a source address not allocated by the AS operator, for legitimate purposes such as Direct Server Return (DSR) deployments.

- A non-BGP customer network that originates traffic with a source address not advertised to the AS operator, also for valid operational reasons.

For ACL-based SAV, enforcing correct filtering in these scenarios requires authoritative information that explicitly specifies which source addresses the host or non-BGP customer is authorized to use. In practice, such authoritative information is often missing.

Existing uRPF-based mechanisms (strict uRPF or loose uRPF) also fail in hidden prefix scenarios. They will drop packets from hidden prefixes because the source addresses are absent from the router's FIB or are received from unexpected interfaces.

# Problem Statement {#sec-problem}

As discussed above, current operational intra-domain SAV mechanisms have significant limitations with respect to automatic updates and accurate validation:

- High operational overhead of ACL-based SAV. ACL-based SAV relies entirely on manual maintenance, resulting in high operational overhead in dynamic networks. To ensure the accuracy of ACL-based SAV, AS operators must manually update ACL rules whenever prefixes or topology change; otherwise, packets may be improperly blocked or permitted.

- Improper block prblem of strict uRPF. Strict uRPF can automatically update SAV rules based on the local FIB information, but it may block legitimate traffic in the asymmetric routing or hidden prefix scenarios. Strict uRPF may mistakenly consider a valid incoming interface as invalid, resulting in legitimate packets being blocked (i.e., an improper block problem).

- Improper permit problem of loose uRPF. Loose uRPF also automatically updates SAV rules based on the local FIB information, but its rules are overly permissive. Any spoofed packet with a source address present in the FIB may be permitted by loose uRPF (i.e., an improper permit problem). 

The fundamental reason these limitations have persisted is the absence of SAV-specific, authoritative information that can be consumed automatically. Current automated uRPF-based mechanisms derive their SAV rules solely from routing or forwarding information. However, routing information is designed to express reachability rather than authorization to use a source address. As a result, uRPF-based mechanisms cannot reliably validate source addresses in scenarios such as asymmetric routing or hidden prefixes. While ACL-based SAV can accurately encode source address authorization, it relies on manual configuration and ongoing operator intervention. Such manual maintenance does not scale in dynamic networks. Consequently, addressing these gaps requires the introduction of SAV-specific, authoritative information and the design of automated mechanisms that can consume this information directly, rather than relying only on routing or forwarding state.

Another consideration is that uRPF-based mechanisms rely on routing information to make SAV decisions, assuming that the routing information in the local FIB is correct. If the routing information is incorrect, SAV decisions may also be incorrect, potentially resulting in improper blocking or permitting. Ensuring the correctness of routing information is the responsibility of mechanisms or operational processes outside the scope of SAV. However, if SAV relies on routing information or other contextual information, it is highly recommended that such information be validated before being used for SAV.

# Requirements for New SAV Mechanisms {#sec-requirement}

This section outlines five general requirements for technical improvements that should be considered when designing future intra-domain SAV architectures and solutions. These informational requirements can not be used to initiate standards-track protocol changes.

## Accurate Validation

Any new intra-domain SAV mechanism MUST improve the accuracy of existing uRPF-based mechanisms by reducing improper blocks and improper permits. Specifically, it MUST satisfy the following:

- MUST result in fewer improper blocks than strict uRPF, particularly in scenarios involving asymmetric routes or hidden prefixes; and
- MUST NOT result in more improper permits than strict uRPF; and  
- MUST result in fewer improper permits than loose uRPF.

To achieve higher SAV accuracy, additional information beyond the local FIB (e.g., SAV-specific information) may be needed to make validation decisions. By integrating such information, routers may have the ability to account for asymmetric routes and hidden prefixes, resulting in more accurate SAV rules.

## Automatic Updates

Any new intra-domain SAV mechanism MUST be capable of automatically generating and updating SAV rules on routers, rather than relying entirely on manual updates as in ACL-based SAV. Automation helps reduce operational complexity and maintenance overhead, while allowing some initial configuration to improve SAV accuracy. This ensures the mechanism is deployable in practical networks without introducing excessive management burden.

## Incremental Deployment Support

Any new intra-domain SAV mechanism MUST support incremental deployment and MUST provide measurable benefits even when only a subset of external non-BGP interfaces has adopted it.

## Fast Convergence

If any new intra-domain SAV mechanism requires disseminating SAV-specific information among intra-domain routers via a protocol, two considerations are essential. First, such mechanism MUST allow routers to learn updated SAV-specific information in a timely manner. Second, such mechanism MUST NOT transmit excessive SAV-specific information via a protocol, as this could significantly increase the burden on the routers’ control planes and potentially degrade the performance of existing protocols.

## Authentication of Information Used for SAV

Any new intra-domain SAV mechanism SHOULD verify the authenticity and trustworthiness of information before using it. Using incorrect information may result in the generation of incorrect SAV rules, potentially permitting spoofed packets or causing legitimate traffic to be blocked. If any new intra-domain SAV mechanism introduces SAV-specific information, it MUST ensure that such information is authenticated. 

## Vulnerability Prevention

Any new intra-domain SAV mechanism MUST NOT introduce additional security vulnerabilities to existing intra-domain architectures or protocols. Protection against compromised or malicious intra-domain routers is out of scope, as such routers can compromise not only SAV mechanisms but also the entire intra-domain routing domain.

# Security Considerations {#sec-security} 

This document discusses the limitations of existing intra-domain SAV practices and identifies problems and informational requirements for improved intra-domain SAV mechanisms. It does not specify new protocols or mechanisms and, as such, does not introduce any new security considerations.

# IANA Considerations {#sec-iana}

This document does not request any IANA allocations.

# Acknowledgements

Many thanks to the valuable comments from: Jared Mauch, Joel Halpern, Aijun Wang, Michael Richardson, Gert Doering, Libin Liu, Li Chen, Tony Przygienda, Yingzhen Qu, James Guichard, Linda Dunbar, Robert Sparks, Stephen Farrel, Ron Bonica, Xueyan Song, etc.

--- back



