---
title: Source Address Validation in Intra-domain Networks Gap Analysis, Problem Statement, and Requirements
abbrev: Intra-domain SAVNET Problem Statement
docname: draft-ietf-savnet-intra-domain-problem-statement-20
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

* Between domains (i.e., autonomous systems) 

Access networks have already deployed SAV mechanisms. These mechanisms typically are deployed on switches and prevent hosts from using the source address of another host on the Internet. Mechanisms include:

* Source Address Validation Improvement (SAVI) Solution for DHCP [RFC7513]

* IP Source Guard (IPSG) based on DHCP snooping [IPSG]

* Cable Source-Verify [cable-verify] 

Sadly, access-network SAV mechanisms are not universally deployed. Therefore, intra-domain (i.e., intra-AS) SAV or/and inter-domain (i.e., inter-AS) SAV are required.

This document analyzes intra-domain SAV and focuses on deployment at external interfaces for verifying incoming traffic. SAV at internal interfaces is considered out of scope. Within a domain (i.e., an autonomous system), an external interfaces may connect to a set of hosts, a non-BGP customer network, or an external AS. As illustrated in {{intra-domain}}, the goals of intra-domain SAV can be summarized as follows:

 * At external interfaces facing hosts or non-BGP customer networks: Prevent them from injecting packets with source addresses they are not authorized to use into the domain

 * At external interfaces facing external ASes: Prevent those ASes from injecting packets with internal-use-only source addresses into the domain

~~~
+---------------------------------------------------+ 
|             Other Autonomous Systems              | 
+---------------------------------------------------+ 
              |                           |           
              |                           |           
              |                           |
+-------------|---------------------------|---------+ 
|   AS        \/                          \/        | 
|         +---#------+               +----#-----+   | 
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
|          \         /                    |         | 
|      +----------------+         +---------------+ | 
|      |Non-BGP Customer|         |     Hosts     | | 
|      |   Network      |         |               | | 
|      |     (P1)       |         |     (P2)      | | 
|      +----------------+         +---------------+ | 
|                                                   | 
+---------------------------------------------------+ 

- SAV at interface 'X' prevents hosts from sending 
  packets with unauthorized source addresses (i.e., 
  addresses outside prefix P2).
- SAV at interface '*' prevents the non-BGP customer
  network from sending packets with unauthorized 
  source addresses (i.e., addresses outside prefix P1).
- SAV at interface '#' prevents the external AS from 
  injecting packets with internal-use-only source 
  addresses (e.g., prefixes P1 and P2).
~~~
{: #intra-domain  title="Goals of intra-domain SAV"}

Building on the last goal of intra-domain SAV, inter-domain SAV additionally prevents other ASes from injecting packets with other spoofed source addresses into the domain.

This document provides a gap analysis of the current operational intra-domain SAV mechanisms, identifies key problems to solve, and proposes basic requirements for solutions.

## Terminology

Non-BGP Customer Network: A stub network connected to one or more routers of the AS for Internet connectivity. It only originates traffic and does not participate in BGP routing exchanges with the AS.

SAV Rule: The rule in a router that describes the mapping relationship between a source address (prefix) and the valid incoming interface(s). It is used by a router to make SAV decisions.

Improper Block: The validation results that the packets with legitimate source addresses are blocked improperly due to inaccurate SAV rules.

Improper Permit: The validation results that the packets with spoofed source addresses are permitted improperly due to inaccurate SAV rules.

SAV-specific Information: The information specialized for SAV rule generation.


## Requirements Language

{::boilerplate bcp14-tagged}

# Current Operational Intra-domain SAV Mechanisms {#sec-mechanisms}

Although BCP 38 [RFC2827] and BCP 84 [RFC3704] specify several ingress filtering methods primarily intended for inter-domain SAV, some of these methods have also been applied to intra-domain SAV in operational practice. This section describes the mechanisms currently used to implement intra-domain SAV.

- Access Control Lists (ACLs) [RFC2827] are SAV filters that check the source address of each packet against a set of permitted or prohibited prefixes. When applied on a router interface, packets that do not match the ACL entries are blocked. ACLs can be deployed on interfaces facing a non-BGP customer network or a set of hosts, permitting only packets with authorized source addresses. They are also commonly used on interfaces facing an external AS to block packets with unacceptable source addresses, such as internal-use-only prefixes. Since ACLs are typically configured and updated manually, timely updates are essential whenever the set of permitted or prohibited prefixes changes.

- Strict uRPF [RFC3704] provides an automated SAV filter by validating the source address of each packet against the router’s local Forwarding Information Base (FIB). A packet is accepted only if (i) the FIB contains a prefix covering the source address, and (ii) the FIB entry’s outgoing interface matches the packet’s incoming interface. Otherwise, the packet is discarded. Strict uRPF is commonly used to block spoofed packets originating from a directly connected host or non-BGP customer network.

- Loose uRPF [RFC3704] also relies on the local FIB for validation, but only checks for the presence of a covering prefix. A packet is accepted if the FIB contains a prefix that covers the source address, regardless of the incoming interface. Loose uRPF is typically used to block spoofed packets that use non-routable or non-global source addresses.

Enhanced Feasible Path uRPF (EFP-uRPF) [RFC8704] is an advanced SAV mechanism specifically designed for inter-domain SAV. It enforces source address validation on router interfaces facing customer ASes by leveraging BGP data received from other ASes. EFP-uRPF is not analyzed in this document, as it is outside the scope of intra-domain SAV.

# Gap Analysis {#sec-gap}

This section analyzes the gaps and key challenges of the current operational intra-domain SAV mechanisms.

## Intra-domain SAV for Traffic from Non-BGP Customer Networks or Directly Connected Hosts {#subsec-gap-1}

To achieve the first goal described in {{sec-intro}}, an AS operator can deploy ACL rules or strict uRPF on the appropriate routers to enforce intra-domain SAV for traffic originating from non-BGP customer networks or directly connected hosts.

For example, an AS operator can configure an ACL on router interfaces facing a non-BGP customer network or directly connected hosts, specifying the set of prefixes authorized for use as source addresses. The router then blocks any packet whose source address falls outside this set. The main drawback of ACL-based SAV is its high operational overhead. Because ACLs are typically maintained manually, operators must update them promptly to reflect changes in prefixes or topology. Failure to do so may result in outdated ACLs that inadvertently block legitimate traffic.

Strict uRPF automatically generates and updates SAV rules, but it may drop legitimate packets in scenarios such as asymmetric routing or hidden prefixes. The following subsections describe two specific gap scenarios that arise when using strict uRPF for intra-domain SAV.

### Asymmetric Routing

Asymmetric routing means a packet traverses from a source to a destination in one path and takes a different path when it returns to the source. Asymmetric routing can occur within an AS due to routing policy, traffic engineering, etc. For example, a non-BGP customer network connected to multiple routers of the AS may need to perform load balancing on incoming traffic, thereby resulting in asymmetric routing.

{{multi-home}} illustrates an example of asymmetric routing. The non-BGP customer network owns prefix 2001:db8::/55 [RFC6890] and connects to two routers of the AS, Router 1 and Router 2. Router 1, Router 2, and Router 3 exchange routing information via the intra-domain routing protocol. To achieve load balancing for inbound traffic, the non-BGP customer network expects traffic destined for 2001:db8:0::/56 to enter through Router 1, and traffic destined for 2001:db8:0:100::/56 to enter through Router 2. To this end, Router 1 advertises 2001:db8:0::/56 and Router 2 advertises 2001:db8:0:100::/56 through the intra-domain routing protocol. {{multi-home}} also shows the corresponding FIB entries of Router 1 and Router 2 for the two prefixes.

~~~
 +----------------------------------------------------------+
 |                                                       AS |
 |                      +----------+                        |
 |                      | Router 3 |                        |
 |                      +----------+                        |
 |                       /       \                          |
 |                      /         \                         |
 |                     /           \                        |
 |            +----------+       +----------+               |
 |            | Router 1 |       | Router 2 |               |
 |            +-------#--+       +----------+               |
 |                    /\           /                        |
 |Traffic with         \          / Traffic with            |
 |source IP addresses   \        /  destination IP addresses|
 |of 2001:db8:0:100::/56 \      \/  of 2001:db8:0:100::/56  |
 |                   +----------------+                     |
 |                   |Non-BGP Customer|                     |
 |                   |    Network     |                     |
 |                   |(2001:db8::/55) |                     |
 |                   +----------------+                     |
 |                                                          |
 +----------------------------------------------------------+

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

While the non-BGP customer network does not expect traffic destined for the prefix 2001:db8:0:100::/56 to arrive via Router 1, it can still send traffic with source addresses within 2001:db8:0:100::/56 to Router 1. As a result, data packets between the non-BGP customer network and Router 1 may follow asymmetric paths. Arrows in the figure indicate the direction of traffic flow.

If Router 1 enforces strict uRPF by checking the FIB entry for the prefix 2001:db8:0:100::/56, the corresponding SAV rule would only allow packets with a source address from 2001:db8:0:100::/56 that arrive via Router 3. Consequently, when the non-BGP customer network sends packets with a source address in 2001:db8:0:100::/56 to Router 1, strict uRPF would incorrectly drop these legitimate packets. Similarly, if Router 2 enforces strict uRPF, it would incorrectly block legitimate packets from the non-BGP customer network that use source addresses within the prefix 2001:db8:0::/56.

### Hidden Prefix

The intra-domain hidden prefix scenario refers to two situations in which a host or non-BGP customer legitimately originates traffic using source addresses that are not visible to the intra-domain routing protocol:

- A host (for example, a cloud server instance operated by a tenant) that originates traffic with a source address not allocated by the AS operator, for legitimate purposes such as Direct Server Return (DSR) deployments.

- A non-BGP customer network that originates traffic with a source address not advertised to the AS operator, also for valid operational reasons.

For ACL-based SAV, enforcing correct filtering in these scenarios requires authoritative information that explicitly specifies which source addresses the host or non-BGP customer is authorized to use. In practice, such authoritative information is often missing.

Existing uRPF-based mechanisms (strict uRPF or loose uRPF) also fail in hidden prefix scenarios. They will drop packets from hidden prefixes because the source addresses are absent from the router's FIB or are received from unexpected interfaces.

## Intra-domain SAV for Traffic from External ASes {#subsec-gap-2}

To achieve the second goal described in {{sec-intro}}, intra-domain SAV is typically deployed on router interfaces facing external ASes to block packets carrying internal-use-only source addresses (see {{inbound-SAV}}). ACL-based SAV is commonly used for this purpose. The AS operator can configure ACL rules containing a set of unacceptable prefixes (for example, internal-use-only prefixes) to block any packet with a source address within these prefixes. However, the operational overhead of maintaining ACL rules can be extremely high, particularly when multiple router interfaces require such configurations, as illustrated in {{inbound-SAV}}.

~~~
+---------------------------------------------------+ 
|             Other Autonomous Systems              | 
+---------------------------------------------------+ 
              | Traffic using internal-   |           
              | use-only source addresses |           
              | (e.g., P1 or P2)          |
+-------------|---------------------------|---------+ 
|   AS        \/                          \/        | 
|         +---#------+               +----#-----+   | 
|         | Router 3 +---------------+ Router 4 |   | 
|         +----------+               +----------+   | 
|          /        \                     |         | 
|         /          \                    |         | 
|        /            \                   |         | 
| +----------+     +----------+      +----------+   | 
| | Router 1 |     | Router 2 +------+ Router 5 |   | 
| +----------+     +----------+      +----------+   | 
|        \             /                  |         | 
|         \           /                   |         | 
|          \         /                    |         | 
|      +----------------+         +---------------+ | 
|      |Non-BGP Customer|         |     Hosts     | | 
|      |   Network      |         |               | | 
|      |     (P1)       |         |     (P2)      | | 
|      +----------------+         +---------------+ | 
|                                                   | 
+---------------------------------------------------+ 
~~~
{: #inbound-SAV title="Intra-domain SAV for traffic from external ASes"}

In addition, loose uRPF can be used in this context to block packets from external ASes that carry non-global or non-routed source addresses. However, it may allow spoofed packets using internal-use-only source addresses, since internal-use-only prefixes exist in the router's local FIB.

# Problem Statement {#sec-problem}

As discussed above, current operational intra-domain SAV mechanisms have significant limitations with respect to automatic updates and accurate validation.

ACL-based SAV relies entirely on manual maintenance, resulting in high operational overhead in dynamic networks. To ensure the accuracy of ACL-based SAV, AS operators must manually update ACL rules whenever prefixes or topology change; otherwise, packets may be improperly blocked or permitted.

Strict uRPF can automatically update SAV rules, but it may block legitimate traffic in the asymmetric routing or hidden prefix scenarios. As discussed in {{subsec-gap-1}}, strict uRPF may mistakenly consider a valid incoming interface as invalid, resulting in legitimate packets being dropped (i.e., an improper block problem).

Loose uRPF is also an automated SAV mechanism, but its rules are overly permissive. As discussed in {{subsec-gap-2}}, any spoofed packet with a source address present in the FIB may be accepted by loose uRPF (i.e., an improper permit problem).

In summary, even if an AS operator has a comprehensive view and can configure correct ACL rules, manual maintenance imposes high operational overhead and may result in improper blocks due to operator oversight. uRPF cannot guarantee the accuracy of SAV because it relies solely on the router’s local FIB to determine SAV rules, which may not correspond to the incoming interfaces of legitimate packets. Consequently, strict uRPF may block legitimate traffic in asymmetric routing and hidden prefix scenarios, while loose uRPF has limited effectiveness against source address spoofing, as it only blocks non-global or non-routed addresses. For hidden prefix scenarios, the key challenge remains how to provide authoritative information that allows the host or non-BGP customer to legitimately use such source addresses.

Another consideration is that uRPF-based mechanisms rely on routing information to make SAV decisions, assuming that the routing information in the local FIB is correct. If the routing information is incorrect, SAV decisions may also be incorrect, potentially resulting in improper blocks or permits. It should be emphasized that ensuring the correctness of routing information is the responsibility of mechanisms or operational processes outside the scope of SAV. Network operators and SAV mechanisms are encouraged to leverage such solutions to validate the routing information used by SAV.


# Requirements for New SAV Mechanisms {#sec-requirement}

This section outlines five general requirements for technical improvements that should be considered when designing future intra-domain SAV architectures and solutions. These informational requirements can not be used to initiate standards-track protocol changes.

## Accurate Validation

The new intra-domain SAV mechanism MUST improve the accuracy of existing intra-domain SAV mechanisms. It MUST achieve the goals described in {{sec-intro}}, preventing spoofed traffic from entering the domain. At the same time, it MUST avoid blocking legitimate packets, particularly in the presence of prefix changes, asymmetric routes, or hidden prefixes. To overcome the improper block problems, routers may need to use additional information (e.g., SAV-specific information) beyond the local FIB information to make SAV decisions. By integrating such information, routers can account for asymmetric routes and hidden prefixes, resulting in more accurate SAV rules.

## Automatic Update

The new intra-domain SAV mechanism MUST be capable of automatically generating and updating SAV rules on routers, rather than relying entirely on manual updates as in ACL-based SAV. Although some initial configuration may be necessary to improve SAV accuracy, automation reduces the subsequent operational overhead for the AS operator.

## Working in Incremental Deployment

The new mechanism MUST support incremental deployment and MUST provide incremental benefits under such partial deployment. In an incremental deployment scenario, the mechanism MUST avoid improper blocks and MUST clearly specify the extent to which the goals described in {{sec-intro}} can be partially achieved.

## Fast Convergence

The new intra-domain SAV mechanism MUST be able to update SAV rules promptly when prefixes, routes, or topology change within an AS. If SAV-specific information is communicated via a protocol, two considerations are essential. First, the mechanism MUST allow routers to learn updated SAV-specific information in a timely manner. Second, the mechanism MUST NOT transmit excessive SAV-specific information, as this could significantly increase the burden on the routers’ control planes and potentially degrade the performance of existing protocols.

## Security

Intra-domain SAV mechanisms MUST NOT introduce additional security vulnerabilities to existing intra-domain architectures or protocols. They MUST ensure the authentication of any SAV-specific information they rely on. Protecting against compromised or malicious intra-domain routers is out of scope, as such routers can compromise not only SAV but the entire intra-domain routing domain.

# Security Considerations {#sec-security} 

This document discusses the limitations of existing intra-domain SAV practices and identifies problems and informational requirements for improved intra-domain SAV mechanisms. It does not specify new protocols or mechanisms and, as such, does not introduce any new security considerations.


# IANA Considerations {#sec-iana}

This document does not request any IANA allocations.

# Acknowledgements

Many thanks to the valuable comments from: Jared Mauch, Joel Halpern, Aijun Wang, Michael Richardson, Gert Doering, Libin Liu, Li Chen, Tony Przygienda, Yingzhen Qu, James Guichard, Linda Dunbar, Robert Sparks, Stephen Farrel, Ron Bonica, etc.

--- back



