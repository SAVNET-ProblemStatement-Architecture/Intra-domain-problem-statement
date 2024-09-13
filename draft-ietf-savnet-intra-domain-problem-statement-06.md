---
title: Source Address Validation in Intra-domain Networks Gap Analysis, Problem Statement, and Requirements
abbrev: Intra-domain SAVNET Problem Statement
docname: draft-ietf-savnet-intra-domain-problem-statement-06
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
  manrs-antispoofing:
    title: MANRS Implementation Guide
    author: 
    org: MANRS
    date: 2023-01
    target: https://www.manrs.org/netops/guide/antispoofing
  nist-rec:
    title: Resilient Interdomain Traffic Exchange - BGP Security and DDoS Mitigation
    author: 
    org: NIST
    date: 2019-01
    target: https://www.nist.gov/publications/resilient-interdomain-traffic-exchange-bgp-security-and-ddos-mitigation"

  
...

--- abstract

This document provides the gap analysis of existing intra-domain source address validation mechanisms, describes the fundamental problems, and defines the requirements for technical improvements.

--- middle

# Introduction {#sec-intro}

Source Address Validation (SAV) is important for defending against source address spoofing attacks. A multi-fence architecture called Source Address Validation Architecture (SAVA) [RFC5210] was proposed to implement SAV at three levels: access network SAV, intra-domain SAV, and inter-domain SAV. When SAV has not been adopted by every source/host, the multi-fence architecture helps enhance the effectiveness of SAV across the whole Internet by preventing or mitigating source address spoofing.

Specifically, access network SAV can ensure that a host must use the source IP address assigned to the host. By deploying access network SAV, hosts in the corresponding access network cannot forge a source address of another host. There are many mechanisms for SAV in access networks. Static ACL rules can be manually configured for validation by specifying which source addresses are acceptable or unacceptable. Dynamic ACL is another efficient mechanism which is associated with authentication servers (e.g., RADIUS and DIAMETER). The servers receive access requests and then install or enable ACL rules on the device to permit particular users' packets. SAVI [RFC7039] represents a kind of mechanism enforcing that the valid source IP address of a host matches the link-layer property of the host's network attachment. For example, SAVI solution for DHCP [RFC7513] creates a binding between a DHCPv4/DHCPv6-assigned IP address and a link-layer property (like MAC address or switch port) on a SAVI device. IP Source Guard (IPSG) {{IPSG}} combined with DHCP snooping is an implementation of SAVI solution for DHCP. Cable Source-Verify {{cable-verify}} also shares some features of SAVI and is used in cable modem networks. Cable modem termination system (CMTS) devices with Cable Source-Verify maintain the bindings of the CPE's IP address, the CPE's MAC address, and the corresponding cable modem identifier. When receiving a packet from a host, the device can check the validity of source IP address according to the bindings.

Given numerous access networks managed by different operators throughout the world, it is difficult to require all access networks to deploy SAV simultaneously. Therefore, intra-domain SAV and inter-domain SAV are needed to block source-spoofed data packets from access networks as close to the source as possible. Intra-domain SAV and inter-domain SAV perform SAV at the granularity of IP prefixes, which is coarser than the granularity of access network SAV (i.e., IP address), as an IP prefix covers a range of IP addresses. 

This document focuses on the analysis of intra-domain SAV. In contrast to inter-domain SAV, intra-domain SAV does not require collaboration between different ASes. Intra-domain SAV rules can be generated by the AS itself. Consider an AS X which provides its host networks or customer networks with the connectivity to the rest of the Internet. Intra-domain SAV for AS X aims at achieving two goals without collaboration with other ASes: i) blocking source-spoofed packets originated from its host networks or customer networks using a source address of other networks; and ii) blocking source-spoofed packets coming from other ASes using a source address of AS X. 

{{intra-domain}} illustrates the goals and function of intra-domain SAV with two cases. Case i shows that the host network or customer network of AS X originates source-spoofed packets using a source address of other networks. If AS X deploys intra-domain SAV, the spoofed packets can be blocked by host-facing routers or customer-facing routers of AS X (i.e., Goal i). Case ii shows that AS X receives source-spoofed packets using a source address of AS X from other ASes (e.g., AS Y). If AS X deploys intra-domain SAV, the spoofed packets from AS Y can be blocked by AS border routers of AS X (i.e., Goal ii). 

~~~
Case i: The host network or customer network of AS X originates    
        packets spoofing source addresses of other networks        
Goal i: If AS X deploys intra-domain SAV,                          
        the spoofed packets can be blocked by AS X                 
                                                                   
                                    Spoofed packets                
                                    using source addresses         
  +-------------------------------+ of other networks     +------+ 
  | Host/Customer Network of AS X |---------------------->| AS X | 
  +-------------------------------+                       +------+ 
                                                                                                                                      
Case ii: AS X receives packets spoofing source addresses of AS X   
         from other ASes (e.g., AS Y)                              
Goal ii: If AS X deploys intra-domain SAV,                         
         the spoofed packets can be blocked by AS X                
                                                                   
           Spoofed packets                                         
           using source addresses                                  
  +------+ of AS X               +------+                          
  | AS X |<----------------------| AS Y |                          
  +------+                       +------+                          
~~~
{: #intra-domain  title="An example for illustrating intra-domain SAV"}

There are many mechanisms for intra-domain SAV. This document provides the gap analysis of existing intra-domain SAV mechanisms. According to the gap analysis, the document concludes the main problems of existing intra-domain SAV mechanisms and describes the requirements for future ones. 

## Terminology

SAV Rule: The rule in a router that describes the mapping relationship between a source address (prefix) and the valid incoming interface(s). It is used by a router to make SAV decisions and is inferred from the SAV Information Base.

SAV Table: The table or data structure that implements the SAV rules and is used for source address validation in the data plane. 

Host-facing Router: An intra-domain router facing an intra-domain host network.

Customer-facing Router: An intra-domain router facing an intra-domain customer network which includes routers and runs the routing protocol.

AS Border Router: An intra-domain router facing an external AS.

Improper Block: The validation results that the packets with legitimate source addresses are blocked improperly due to inaccurate SAV rules.

Improper Permit: The validation results that the packets with spoofed source addresses are permitted improperly due to inaccurate SAV rules.


## Requirements Language

{::boilerplate bcp14-tagged}

# Existing Mechanisms {#sec-mechanisms}

This section briefly introduces existing intra-domain SAV mechanisms. Particularly, ingress filtering (i.e., BCP38 {{RFC2827}} and BCP84 {{RFC3704}}) is the best current practice for intra-domain SAV.

- ACL-based ingress filtering {{RFC2827}} is a typical mechanism for intra-domain SAV. It requires that network operators manually configure ACL rules on intra-domain routers to block or permit data packets using specific source addresses. This mechanism can be used on interfaces of host-facing or customer-facing routers facing an intra-domain host/customer network to prevent the corresponding host/customer network from spoofing source prefixes of other networks {{manrs-antispoofing}}. In addition, it is also usually used on interfaces of AS border routers facing an external AS to block data packets using disallowed source addresses, such as internal source addresses owned by the local AS <xref target="nist-rec"/>. In any application scenario, ACL rules must be updated in time to be consistent with the latest filtering criteria when the network changes.

- Strict uRPF [RFC3704] is another typical intra-domain SAV mechanism. It is typically used on interfaces of host-facing or customer-facing routers facing an intra-domain host/customer network. Routers deploying strict uRPF accept a data packet only when i) the local FIB contains a prefix covering the packet's source address and ii) the corresponding outgoing interface for the prefix in the FIB matches the packet's incoming interface. Otherwise, the packet will be blocked.

- Loose uRPF [RFC3704] uses a pretty looser validation method which loses the directionality. A packet will be accepted if the router's local FIB contains a prefix covering the packet's source address regardless of the interface from which the packet is received. In fact, interfaces of AS border routers facing an external AS may use loose uRPF to block incoming data packets using non-global addresses {{nist-rec}}. 

- Carrier Grade NAT has some operations on the source addresses of packets, but it is not an anti-spoofing tool, as described in {{manrs-antispoofing}}. If the source address of a packet is in the INSIDE access list, the NAT rule can translate the source address to an address in the pool OUTSIDE. The NAT rule cannot determine whether the source address is spoofed or not. In addition, the packet using a spoofed source address will still be forwarded if the spoofed source address is not included in the INSIDE access list. Therefore, Carrier Grade NAT cannot help identify and block source-spoofed data packets. 


# Gap Analysis {#sec-gap}

Towards the two goals of intra-domain SAV in {{intra-domain}}, intra-domain SAV is commonly deployed on host-facing routers, customer-facing routers, and AS border routers. This section elaborates the key problems of SAV on host-facing or customer-facing routers and SAV on AS border routers, respectively. Since existing intra-domain SAV mechanisms either require high operational overhead or have limitations in accuracy, they will improperly block data packets using a legitimate source address (i.e., improper block) or improperly permit data packets using a spoofed source address (i.e., improper permit).

## SAV on Host-facing or Customer-facing Routers

Towards Goal i in {{intra-domain}}, intra-domain SAV is typically deployed on interfaces of host-facing or customer-facing routers facing an intra-domain host/customer network to validate data packets originated from that network, since SAV is more effective when deployed closer to the source. 

As described previously, ACL rules can be configured on such interfaces for ingress filtering. These ACL rules must be manually updated according to prefix changes or topology changes in a timely manner. Otherwise, if ACL rules are not updated in time, improper block or improper permit problems may occur. To ensure the accuracy of ACL rules in dynamic networks, high operational overhead will be induced to achieve timely updates for ACL configurations. 

Strict uRPF can also be used for SAV on host-facing or customer-facing routers. It can generate and update SAV rules in an automatic way but it will cause improper blocks in the scenario of asymmetric routing or hidden prefix. 


### Asymmetric Routing

{{multi-home}} shows asymmetric routing in a multi-homing scenario. In the figure, Network 1 is a host/customer network of the AS. It owns prefix 192.0.2.0/24 [RFC6890] and is attached to two intra-domain routers, i.e., Router 1 and Router 2. For the load balance purpose of traffic flowing to Network 1, Network 1 expects the incoming traffic destined for the sub-prefix 192.0.2.128/25 to come only from Router 1 and the incoming traffic destined for the other sub-prefix 192.0.2.0/25 to come only from Router 2. To this end, Router 1 only learns the route to sub-prefix 192.0.2.128/25 from Network 1, while Router 2 only learns the route to the other sub-prefix 192.0.2.0/25 from Network 1. Then, Router 1 and Router 2 distribute the sub-prefix information to routers in the AS through intra-domain routing protocols such as OSPF or IS-IS. Finally, Router 1 learns the route to 192.0.2.0/25 from Router 3, and Router 2 learns the route to 192.0.2.128/25 from Router 3. The FIBs of Router 1 and Router 2 are shown in the figure. Although Network 1 does not expect traffic destined for 192.0.2.0/25 to come from Router 1, it may send traffic with source addresses of prefix 192.0.2.0/25 to Router 1 for load balance of traffic originated from Network 1. As a result, there is asymmetric routing of data packets between Network 1 and Router 1. Arrows in the figure indicate the flowing direction of traffic. Similarly, Network 1 may also send traffic with source addresses of prefix 192.0.2.128/25 to Router 2, resulting in asymmetric routing between Network 1 and Router 2. In addition to the traffic engineering mentioned above, other factors may also cause similar asymmetric routing between host-facing/customer-facing routers and host/customer networks.

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

 The legitimate traffic originated from Network 1 with source IP 
 addresses of 192.0.2.0/25 will be improperly blocked by Router 1 
 if Router 1 uses strict uRPF.
~~~
{: #multi-home title="Asymmetric routing in multi-homing scenario"}

Strict uRPF takes the entries in FIB for SAV. It will improperly block data packets which use legitimate source addresses when asymmetric routing exists. In the figure, if Router 1 uses strict uRPF on interface '#', the SAV rule is that Router 1 only accepts packets with source addresses of 192.0.2.128/25 from Network 1. Therefore, when Network 1 sends packets with source addresses of 192.0.2.0/25 to Router 1, strict uRPF at Router 1 will improperly block these legitimate packets. Similarly, when Router 2 uses strict uRPF on its interface '#' and receives packets with source addresses of prefix 192.0.2.128/25 from Network 1, it will also improperly block these legitimate packets because strict uRPF at Router 2 will only accept packets from Network 1 using source addresses of prefix 192.0.2.0/25. 

### Hidden Prefix

For special business purposes, a host/customer network will originate data packets using a source address that is not distributed through intra-domain routing protocol. In other words, the IP address/prefix is hidden from intra-domain routing protocol and intra-domain routers. In this scenario, strict uRPF on host-facing or customer-facing routers will improperly block data packets from the host/customer network using source addresses in a hidden prefix.

~~~
          +-------------------------+                             
          |          AS Y           | AS Y announces the route    
          |   (where the anycast    | for anycast prefix P3
          |    server is located)   | in BGP                            
          +-----------+-------------+                             
                      |                                           
                      |                                           
          +-----------+-------------+                             
          |       Other ASes        |                             
          +-------------------------+                             
             /                    \                               
            /                      \                              
           /                        \                             
+------------------+   +---------------------------------------+   
|      AS Z        |   |         +----------+             AS X |   
| (where the user  |   |         | Router 4 |                  |   
|    is located)   |   |         +----------+                  |   
+------------------+   |              |                        |   
                       |              |                        |   
                       |         +----+-----+                  |   
                       |         | Router 5 |                  |   
                       |         +----#-----+                  |   
                       |              /\    DSR responses with |   
                       |              |     source IP addresses|   
                       |              |     of P3              |   
                       |       +---------------+               |   
                       |       | Host/Customer |               |   
                       |       |   Network 2   |               |   
                       |       |     (P2)      |               |   
                       |       +---------------+               |   
                       | (where the edge server is located)    |   
                       +---------------------------------------+   
DSR response packets from edge server in Network 2 with 
source IP addresses of P3 (i.e., the anycast prefix) will 
be improperly blocked by Router 5 if Router 5 uses strict uRPF.
~~~
{: #hidden title="Hidden prefix in CDN and DSR scenario"}

The Content Delivery Networks (CDN) and Direct Server Return (DSR) scenario is a representative example of hidden prefix. In this scenario, the edge server in an AS will send DSR response packets using a source address of the anycast server which is located in another remote AS. However, the source address of anycast server is hidden from intra-domain routing protocol and intra-domain routers in the local AS. While this is an inter-domain scenario, we note that DSR response packets may also be improperly blocked by strict uRPF when edge server is located in the host/customer network. For example, in {{hidden}}, assume edge server is located in Host/Customer Network 2 and Router 5 only learns the route to P2 from Network 2. When edge server receives the request from the remote anycast server, it will directly return DSR response packets using the source address of anycast server (i.e., P3). If Router 5 uses strict uRPF on interface '#', the SAV rule is that Router 5 only accepts packets with source addresses of P2 from Network 2. As a result, DSR response packets will be blocked by strict uRPF on interface '#'.


## SAV on AS Border Routers

Towards Goal ii in {{intra-domain}}, intra-domain SAV is typically deployed on interfaces of AS border routers facing an external AS to validate packets arriving from other ASes. {{inbound-SAV}} shows an example of SAV on AS border routers. In the figure, Router 3 and Router 4 deploy intra-domain SAV on interface '#' for validating data packets coming from external ASes.

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

ACL-based ingress filtering is usually used for this purpose. By configuring specified ACL rules, data packets that use disallowed source addresses (e.g., non-global addresses or internal source addresses) can be blocked at AS border routers. As mentioned above, ACL-based ingress filtering requires manual updates when internal source prefixes change dynamically. If ACL rules are not updated in time, there may be improper block or improper permit problems. The operational overhead of maintaining updated ACL rules will be extremely high when there are multiple AS border routers adopting SAV as shown in {{inbound-SAV}}. 

In addition to ACL-based ingress filtering, loose uRPF is also often used for SAV on AS border routers and is more adaptive than ACL-based rules. But it sacrifices the directionality of SAV and has limited blocking capability, because it allows packets with source addresses that exist in the FIB table on all router interfaces. 


# Problem Statement {#sec-problem}

Accurate validation and low operational overhead are two important design goals of intra-domain SAV mechanisms. However, as analyzed above, existing intra-domain SAV mechanisms have problems of inaccurate validation or high operational overhead. 

ACL-based ingress filtering relies on manual configurations and thus requires high operational overhead in dynamic networks. To guarantee accuracy of ACL-based SAV, network operators have to manually update the ACL-based filtering rules in time when the prefix or topology changes. Otherwise, improper block or improper permit problems may appear. 

Strict uRPF can automatically update SAV rules, but may improperly block legitimate traffic under asymmetric routing scenario or hidden prefix scenario. The root cause is that strict uRPF uses the router's local FIB to determine the valid incoming interface for a specific source address, which may not match the real incoming direction from the source, due to the existence of asymmetric routes. Hence, it may mistakenly consider a valid incoming interface as invalid, resulting in improper block problems; or it may mistakenly consider an invalid incoming interface as valid, resulting in improper permit problems. 

Loose uRPF is also an automated SAV mechanism but its SAV rules are overly loose. Most spoofed packets will be improperly permitted by loose uRPF. 


# Requirements for New SAV Mechanisms {#sec-requirement}

This section lists the requirements which can be a guidance for narrowing the gaps of existing intra-domain SAV mechanisms. The requirements can be fully or partially fulfilled when designing new intra-domain SAV mechanisms. 

## Automatic Update

The new intra-domain SAV mechanism MUST be able to automatically adapt to network dynamics such as routing changes or prefix changes, instead of purely relying on manual update. 

## Accurate Validation

The new intra-domain SAV mechanism need to improve the validation accuracy upon existing intra-domain SAV mechanisms. In a static network, improper block MUST be avoided to guarantee that legitimate traffic will not be blocked. Improper permit SHOULD be reduced as much as possible so that the malicious packets with forged source addresses can be efficiently filtered. When there are network changes, the new mechanisms MUST update SAV rules efficiently for keeping the high accuracy of validation. 

## Working in Incremental/Partial Deployment

The new intra-domain SAV mechanism SHOULD NOT assume pervasive adoption, and some routers that intend to adopt the new mechanism may not be able to be upgraded immediately. The new intra-domain SAV mechanism SHOULD be able to provide incremental protection when it is incrementally deployed. The effectiveness of the new intra-domain SAV mechanism under incremental deployment SHOULD be no worse than existing ones. 

## Fast Convergence

The new intra-domain SAV mechanism MUST adapt to prefix changes, route changes, and topology changes in an intra-domain network, and update SAV rules in a timely manner. In addition, it MUST consider how to update SAV rules proactively or reactively so as to minimize improper blocks during convergence.

## Necessary Security Guarantee

Necessary security tools SHOULD be considered in the new intra-domain SAV mechanism. These security tools can help protect the SAV rule generation process. {{sec-security} details the security scope and considerations for the new intra-domain SAV mechanism. 


# Intra-domain SAV Scope {#sec-scope}

The new intra-domain SAV mechanisms work in the same scenarios as existing intra-domain SAV mechanisms. Generally, the scope includes all IP-encapsulated scenarios: 

- Native IP forwarding: including both forwarding based on global routing table and CE site forwarding of VPN. 
- IP-encapsulated Tunnel (IPsec, GRE, SRv6, etc.): focusing on the validation of the outer layer IP address. 
- Validating both IPv4 and IPv6 addresses. 

Scope does not include:

- Non-IP packets: including MPLS label-based forwarding and other non-IP-based forwarding. 

In addition, the new intra-domain SAV mechanisms SHOULD avoid data-plane packet modification. Existing architectures or protocols or mechanisms can be used in the new SAV mechanisms to achieve better SAV function. 


# Security Considerations {#sec-security}

The new intra-domain SAV mechanisms should not introduce additional security vulnerabilities or confusion to the existing intra-domain architectures or control or management plane protocols. 

Similar to the security scope of intra-domain routing protocols, intra-domain SAV mechanisms should ensure integrity and authentication of protocol messages that deliver the required SAV information, but it is not necessary to provide protection against compromised or misconfigured intra-domain routers which poison existing control or management plane protocols. Compromised or misconfigured intra-domain routers will not only affect SAV, but also disrupt the whole intra-domain routing domain, which is beyond the capability of intra-domain SAV.


# IANA Considerations {#sec-iana}

This document does not request any IANA allocations.

# Acknowledgements

Many thanks to the valuable comments from: Jared Mauch, Barry Greene, Fang Gao, Kotikalapudi Sriram, Anthony Somerset, Yuanyuan Zhang, Igor Lubashev, Alvaro Retana, Joel Halpern, Aijun Wang, Michael Richardson, Li Chen, Gert Doering, Mingxing Liu, Libin Liu, John O'Brien, Roland Dobbins, Xiangqing Chang, Tony Przygienda, Yingzhen Qu, Changwang Lin, etc.

--- back



