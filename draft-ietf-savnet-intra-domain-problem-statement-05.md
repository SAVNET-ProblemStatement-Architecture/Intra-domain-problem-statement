---
title: Source Address Validation in Intra-domain Networks Gap Analysis, Problem Statement, and Requirements
abbrev: Intra-domain SAVNET Problem Statement
docname: draft-ietf-savnet-intra-domain-problem-statement-05
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
  manrs-antispoofing:
    title: MANRS Implementation Guide
    author: 
    org: MANRS
    date: 2023-01
    target: https://www.manrs.org/netops/guide/antispoofing
  nist-rec:
    title: Resilient Interdomain Traffic Exchange - BGP Security and DDos Mitigation
    author: 
    org: NIST
    date: 2019-01
    target: https://www.nist.gov/publications/resilient-interdomain-traffic-exchange-bgp-security-and-ddos-mitigation"
  RFC2827:
  RFC3704:
  RFC5210:

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
  RFC7039:
  RFC7513:
  RFC6890:

  
...

--- abstract

This document provides the gap analysis of existing intra-domain source address validation mechanisms, describes the fundamental problems, and defines the requirements for technical improvements.

--- middle

# Introduction {#sec-intro}
Source Address Validation (SAV) is important for defending against source address spoofing attacks and allowing accurate traceback. A multi-fence architecture called Source Address Validation Architecture (SAVA) [RFC5210] was proposed to validate source addresses at three levels: access network SAV, intra-domain SAV, and inter-domain SAV. When SAV is not fully enabled at the edge of the Internet, the multi-fence architecture can help enhance the validation across the whole Internet and thus reduce the opportunities of launching source address spoofing attacks.

Particularly, access network SAV ensures that a host uses a valid address assigned to the host statically or dynamically. In this way, the host cannot use the source address of another host. There are many mechanisms for SAV in access networks. Static ACL rules can be manually configured for validation by specifying which source addresses are acceptable or unacceptable. Dynamic ACL is another efficient mechanism which is associated with authentication servers (e.g., RADIUS and DIAMETER). The servers receive access requests and then install or enable ACL rules on the device to permit particular users' packets. SAVI [RFC7039] represents a kind of mechanism enforcing that the legitimate IP address of a host matches the link-layer property of the host's network attachment. For example, SAVI solution for DHCP [RFC7513] creates a binding between a DHCPv4/DHCPv6-assigned IP address and a link-layer property (like MAC address or switch port) on a SAVI device. IP Source Guard (IPSG) {{IPSG}} combined with DHCP snooping is an implementation of SAVI solution for DHCP. Cable Source-Verify {{cable-verify}} also shares some features of SAVI and is used in cable modem networks. Cable modem termination system (CMTS) devices with Cable Source-Verify maintain the bindings of the CPE's IP address, the CPE's MAC address, and the corresponding cable modem identifier. When receiving packets, the device will check the validity of the packets according to the bindings.

Given numerous access networks managed by different operators throughout the world, it is difficult to require all access networks to effectively deploy SAV. Therefore, intra-domain SAV and inter-domain SAV are needed to block spoofing traffic as close to the source as possible. Both intra-domain SAV and inter-domain SAV usually perform validation at the granularity of IP prefixes, which is coarser than the validation granularity of access network SAV, as an IP prefix covers a range of IP addresses. 

This document focuses on the analysis of intra-domain SAV. In contrast to inter-domain SAV, intra-domain SAV does not require collaboration between different ASes. The SAV rules can be generated by the AS itself. Consider an AS X which provides its host networks or customer networks with the connectivity to other ASes. The intra-domain SAV for AS X has two goals: i) blocking the illegitimate packets originating from its host networks or customer networks with spoofed source addresses; and ii) blocking the illegitimate packets coming from other ASes which spoof the source addresses of AS X. 

{{intra-domain}} illustrates the function of intra-domain SAV with two cases. Case i shows that AS X forwards source-spoofed packets originating from its host networks or customer networks to other ASes (e.g., AS Y). If AS X deploys intra-domain SAV, the source-spoofed packets from its host networks or customer networks can be blocked by AS X itself (i.e., Goal i). Case ii shows that AS X receives the packets which spoof AS X's source addresses from other ASes (e.g., AS Y). If AS X deploys intra-domain SAV, the spoofed packets from AS Y can be blocked by AS X (i.e., Goal ii). 

~~~
Case i: AS X forwards spoofed packets originating from its 
        host networks or customer networks to other ASes (e.g., AS Y)
Goal i: If AS X deploys intra-domain SAV, 
        the spoofed packets can be blocked by AS X

  +------+  Spoofed packets  +------+
  | AS X |------------------>| AS Y |
  +------+                   +------+


Case ii: AS X receives packets spoofing 
         AS X's source addresses from other ASes (e.g., AS Y)
Goal ii: If AS X deploys intra-domain SAV,
         the spoofed packets can be blocked by AS X

  +------+  Spoofed packets  +------+
  | AS X |<------------------| AS Y |
  +------+                   +------+
~~~
{: #intra-domain  title="An example for illustrating intra-domain SAV"}

There are many mechanisms for intra-domain SAV. This document provides the gap analysis of existing intra-domain SAV mechanisms. According to the gap analysis, the document concludes the main problems of existing mechanisms and describes the requirements for future intra-domain SAV mechanisms. 

## Terminology

SAV Rule: The rule in a router that describes the mapping relationship between a source address (prefix) and the valid incoming interface(s). It is used by a router to make SAV decisions and is inferred from the SAV Information Base.

SAV Table: The table or data structure that implements the SAV rules and is used for source address validation in the data plane. 

Host-facing Router: An intra-domain router of an AS which is connected to a host network (i.e., a layer-2 network).

Customer-facing Router: An intra-domain router of an AS which is connected to a customer network running the routing protocol (i.e., a layer-3 network).

AS Border Router: An intra-domain router of an AS which is connected to other ASes.

Improper Block: The validation results that the packets with legitimate source addresses are blocked improperly due to inaccurate SAV rules.

Improper Permit: The validation results that the packets with spoofed source addresses are permitted improperly due to inaccurate SAV rules.


## Requirements Language

{::boilerplate bcp14-tagged}

# Existing Mechanisms {#sec-mechanisms}
Ingress filtering {{RFC2827}}{{RFC3704}} is the current practice of intra-domain SAV. This section briefly introduces the existing intra-domain SAV mechanisms. 

- ACL-based ingress filtering {{RFC2827}}{{RFC3704}} is a typical mechanism for intra-domain SAV. ACL rules can be configured for blocking or permitting packets with specific source addresses. This mechanism can be applied at the downstream interfaces of host-facing routers or customer-facing routers {{manrs-antispoofing}}. The validation at downstream interfaces will prevent the corresponding host networks or customer networks from spoofing source prefixes of other networks. In addition, at the upstream interfaces of AS border routers, ACL can be enabled for blocking packets with disallowed source prefixes, such as the internal source prefixes owned by the AS <xref target="nist-rec"/>. In any application scenario, ACL rules should be updated in time to be consistent with the latest filtering criteria. 

- Strict uRPF [RFC3704] is another commonly used mechanism for SAV in intra-domain networks. Routers deploying strict uRPF accept a data packet only when i) the local FIB contains a prefix encompassing the packet's source address and ii) the corresponding outgoing interface for the prefix in the FIB matches the packet's incoming interface. Otherwise, the packet will be blocked. Strict uRPF is usually used at downstream interfaces of host-facing routers or customer-facing routers. 

- Loose uRPF [RFC3704] takes a looser validation mechanism than strict uRPF to avoid improper block. A packet will be accepted if the local FIB contains a prefix encompassing the packet's source address regardless of the interface from which the packet is received. Upstream interfaces of AS border routers can enable loose uRPF for blocking non-global addresses {{nist-rec}}. 

- Carrier Grade NAT has some operations on the source addresses of packets, but is not an anti-spoofing tool, as described in {{manrs-antispoofing}}. If the source address of a packet is in the INSIDE access list, the NAT rule can translate the source address to an address in the pool OUTSIDE. The NAT rule cannot judge whether the source address is spoofed or not. In addition, the packet with a spoofed source address will be forwarded directly if the spoofed source address is not included in the INSIDE access list. Therefore, Carrier Grade NAT cannot help block or traceback spoofed packets, and other SAV mechanisms are still needed. 


# Gap Analysis {#sec-gap}
Existing intra-domain SAV mechanisms either require high operational overhead or have limitations in accuracy. They may improperly block the traffic with legitimate source addresses (i.e., improper block) or improperly permit the traffic with spoofed source addresses (i.e., improper permit). 

## SAV on Host-facing or Customer-facing Routers

Towards the Goal i in {{intra-domain}}, intra-domain SAV is typically adopted at downstream interfaces of host-facing or customer-facing routers to validate packets from intra-domain host networks or customer networks, since it is most effective closer to the edges of the Internet. As described previously, ACL rules can be configured at downstream interfaces for ingress filtering. These rules need to be updated when prefixes or topologies of host networks or customer networks change. If ACL rules are not updated in time, improper block or improper permit may occur. To ensure the accuracy of SAV in dynamic networks, high operational overhead will be induced to achieve timely updates for ACL configurations. 

Strict uRPF can also be used for SAV on host-facing or customer-facing routers, but there may be improper block problem in multi-homing and asymmetric routing scenario. {{multi-home}} shows such a case. In the figure, Network 1 is a host/customer network of the AS. It owns prefix 192.0.2.0/24 [RFC6890] and is attached to two intra-domain edge routers, i.e., Router 1 and Router 2. For the load balance purpose of traffic flowing to Network 1, Network 1 expects the incoming traffic destined for the sub-prefix 192.0.2.128/25 to come only from Router 1 and the incoming traffic destined for the other sub-prefix 192.0.2.0/25 to come only from Router 2. To this end, Router 1 only learns the route to sub-prefix 192.0.2.128/25 from Network 1, while Router 2 only learns the route to the other sub-prefix 192.0.2.0/25 from Network 1. Then, Router 1 and Router 2 advertise the sub-prefix information to routers in the AS through intra-domain routing protocols such as OSPF or IS-IS. Finally, Router 1 learns the route to 192.0.2.0/25 from Router 3, and Router 2 learns the route to 192.0.2.128/25 from Router 3. The FIBs of Router 1 and Router 2 are shown in the figure. Although Network 1 does not expect traffic destined for 192.0.2.0/25 to come from Router 1, it may send traffic with source addresses of prefix 192.0.2.0/25 to Router 1 for load balance of traffic originating from Network 1. As a result, there is asymmetric routing of data packets between Network 1 and Router 1. Arrows in the figure indicate the direction of traffic. Similarly, Network 1 may also send traffic with source addresses of prefix 192.0.2.128/25 to Router 2, resulting in asymmetric routing between Network 1 and Router 2. 

~~~
 +---------------------------------------------------------------+
 |                                                           AS  |
 |                         +----------+                          |
 |                         | Router 3 |                          |
 |FIB of Router 1          +----------+  FIB of Router 2         |
 |Dest           Next_hop    /      \    Dest           Next_hop |
 |192.0.2.128/25 Network 1  /        \   192.0.2.0/25   Network 1|
 |192.0.2.0/25   Router 3  /          \  192.0.2.128/25 Router 3 |
 |                  +----------+     +----------+                |
 |                  | Router 1 |     | Router 2 |                |
 |                  +-----+#+--+     +-+#+------+                |
 |                        /\           /                         |
 |     Traffic with        \          / Traffic with             |
 |     source IP addresses  \        /  destination IP addresses |
 |     of 192.0.2.0/25       \      \/  of 192.0.2.0/25          |
 |                      +----------------+                       |
 |                      |  Host/Customer |                       |
 |                      |    Network 1   |                       |
 |                      | (192.0.2.0/24) |                       |
 |                      +----------------+                       |
 |                                                               |
 +---------------------------------------------------------------+

 The legitimate traffic originating from Network 1 with source IP 
 addresses of 192.0.2.0/25 will be improperly blocked by Router 1 
 if Router 1 uses strict uRPF.
~~~
{: #multi-home title="Asymmetric routing in the multi-homing scenario"}

Strict uRPF takes the entries in FIB for SAV. It can improperly block data packets that use legitimate source IP addresses when asymmetric routing exists. In the figure, if Router 1 applies strict uRPF at interface '#', the SAV rule is that Router 1 only accepts packets with source addresses of 192.0.2.128/25 from Network 1. Therefore, when Network 1 sends packets with source addresses of 192.0.2.0/25 to Router 1, strict uRPF at Router 1 will improperly block these legitimate packets. Similarly, when Router 2 with strict uRPF deployed receives packets with source addresses of prefix 192.0.2.128/25 from Network 1, it will also improperly block these legitimate packets because strict uRPF at Router 2 will only accept packets from Network 1 using source addressses of prefix 192.0.2.0/25. Therefore, strict uRPF may cause improper block problem in the case of asymmetric routing. 


## SAV on AS Border Routers

Towards the Goal ii in {{intra-domain}}, intra-domain SAV is typically adopted at upstream interfaces of AS border routers to validate the packets from other ASes. {{inbound-SAV}} shows an example of SAV on AS border routers. In the figure, Router 3 and Router 4 deploy SAV mechanisms at interface '#' for validating data packets coming from external ASes.

ACL-based ingress filtering is usually used for this purpose. By configuring specified ACL rules, data packets that use disallowed source addresses (e.g., non-global addresses or the internal source prefixes) can be blocked at AS border routers. As mentioned above, ACL-based ingress filtering requires timely updates when the routing status changes dynamically. When the ACL rules are not updated in time, there may be improper block or improper permit problems. The operational overhead of maintaining updated ACL rules will be extremely high when there are multiple AS border routers adopting SAV as shown in {{inbound-SAV}}. 

In addition to ACL-based ingress filtering, loose uRPF is also often used for SAV on AS border routers and is more adaptive than ACL-based rules. But it sacrifices the directionality of SAV and has limited blocking capability, because it allows packets with source addresses that exist in the FIB table at all router interfaces. 

~~~
 Packets with +              Packets with +
 spoofed P1/P2|              spoofed P1/P2|
+-------------|---------------------------|---------+
|   AS        \/                          \/        |
|         +--+#+-----+               +---+#+----+   |
|         | Router 3 +---------------+ Router 4 |   |
|         +----------+               +----+-----+   |
|          /        \                     |         |
|         /          \                    |         |
|        /            \                   |         |
| +----------+     +----------+      +----+-----+   |
| | Router 1 |     | Router 2 |      | Router 5 |   |
| +----------+     +----------+      +----+-----+   |
|        \             /                  |         |
|         \           /                   |         |
|          \         /                    |         |
|       +---------------+         +-------+-------+ |
|       |     Host      |         |   Customer    | |
|       |   Network     |         |   Network     | |
|       |     (P1)      |         |     (P2)      | |
|       +---------------+         +---------------+ |
|                                                   |
+---------------------------------------------------+
~~~
{: #inbound-SAV title="An example of SAV on AS border routers"}


# Problem Statement {#sec-problem}

Accurate validation and low operational overhead are two important design goals of intra-domain SAV mechanisms. As analyzed above, asymmetric routing and dynamic networks are two challenging scenarios for the two goals. In these scenarios, existing SAV mechanisms have problems of inaccurate validation or high operational overhead. 

ACL-based SAV relies on manual configurations and thus requires high operational overhead in dynamic networks. Operators have to manually update the ACL-based filtering rules in time when the prefix or topology changes. Otherwise, improper block or improper permit problems may appear. 

Strict uRPF-based SAV can automatically update SAV rules, but may improperly block legitimate traffic under asymmetric routing. The root cause is that strict uRPF leverages the local FIB table to determine the incoming interface for source addresses, which may not match the real data-plane forwarding path from the source, due to the existence of asymmetric routes. Hence, it may mistakenly consider a valid incoming interface as invalid, resulting in improper block problem; or it may consider an invalid incoming interface as valid, resulting in improper permit problem. 

Loose uRPF is also an automated SAV mechanism but its SAV rules are overly loose. Most spoofed packets will be improperly permitted by adopting loose uRPF. 


# Requirements for New SAV Mechanisms {#sec-requirement}

This section lists the requirements which can be a guidance for narrowing the gaps of existing intra-domain SAV mechanisms. The requirements can be fully or partially fulfilled when designing new intra-domain SAV mechanisms. 

## Automatic Update

The new intra-domain SAV mechanisms MUST be able to automatically adapt to network dynamics such as routing change or prefix change, instead of purely relying on manual update. 

## Accurate Validation

The new intra-domain SAV mechanisms needs to improve the validation accuracy upon existing intra-domain SAV mechanisms. In a static network, improper block MUST be avoided to guarantee that legitimate traffic will not be blocked. Improper permit SHOULD be reduced as much as possible so that the malicious packets with forged source addresses can be efficiently filtered. When there are network changes, the new mechanisms MUST update SAV rules efficiently for keeping the high accuracy of validaiton. 

## Working in Incremental/Partial Deployment

The new intra-domain SAV mechanisms SHOULD NOT assume pervasive adoption. Some routers may not be able to be easily upgraded for supporting the new SAV mechanism due to their limitations of capabilities, versions, or vendors. The mechanisms SHOULD be able to provide protection even when it is partially deployed. The effectiveness of protection for the new intra-domain SAV mechanisms under partial deployment SHOULD be no worse than existing mechanisms. 

## Fast Convergence

Network changes may cause SAV rules to be inaccurate and need to be updated. The new intra-domain SAV mechanism MUST consider how to update SAV rules quickly so as to minimize improper block and improper permit impacts during convergence.

## Necessary Security Guarantee

Necessary security tools SHOULD be contained in the new intra-domain SAV mechanisms. In an insecure scenario, these security tools can help protect the SAV rule generation process. 


# Intra-domain SAV Scope {#sec-scope}

The new intra-domain SAV mechanisms work in the same scenarios as existing intra-domain SAV mechanisms. Generally, it includes all IP-encapsulated scenarios: 

- Native IP forwarding: including both forwarding based on global routing table and CE site forwarding of VPN. 
- IP-encapsulated Tunnel (IPsec, GRE, SRv6, etc.): focusing on the validation of the outer layer IP address. 
- Validating both IPv4 and IPv6 addresses. 

Scope does not include:

- Non-IP packets: including MPLS label-based forwarding and other non-IP-based forwarding. 

In addition, the new intra-domain SAV mechanisms SHOULD avoid data-plane packet modification. Existing architectures or protocols or mechanisms can be used in the new SAV mechanisms to achieve better SAV function. 


# Security Considerations {#sec-security}

The new intra-domain SAV mechanisms MUST NOT introduce additional security vulnerabilities or confusion to the existing intra-domain architectures or control or management plane protocols. Similar to the security scope of intra-domain routing protocols, intra-domain SAV mechanisms SHOULD ensure integrity and authentication of protocol packets that deliver the required SAV information. 

The new intra-domain SAV mechanisms do not provide protection against compromised or misconfigured routers that poison existing control plane protocols. Such routers can not only disrupt the SAV function, but also affect the entire routing domain. 


# IANA Considerations {#sec-iana}

This document does not request any IANA allocations.

# Acknowledgements

Many thanks to the valuable comments from: Jared Mauch, Barry Greene, Fang Gao, Kotikalapudi Sriram, Anthony Somerset, Yuanyuan Zhang, Igor Lubashev, Alvaro Retana, Joel Halpern, Aijun Wang, Michael Richardson, Li Chen, Gert Doering, Mingxing Liu, Libin Liu, John O'Brien, Roland Dobbins, Xiangqing Chang, etc.

--- back



