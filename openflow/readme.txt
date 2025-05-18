
Part 3: Shortest Path Switching (SPS)
_____________________________________

Overview:
---------
The ShortestPathSwitching module is a Floodlight application that installs flow rules in SDN switches to ensure that packets are forwarded across the shortest valid path to their destinations. The implementation adheres strictly to the assignment specification and avoids all broadcast behavior, instead relying on global network knowledge to manage routing deterministically.

Key Design Decisions:
---------------------
- Global Topology Awareness: Topology information was gathered through the ILinkDiscoveryService, and all shortest path calculations were done at the controller using a variant of Dijkstra’s algorithm.
- Bidirectional Connectivity: For every pair of known hosts, the controller installs rules to ensure both directions of communication are covered.
- Dual Match Criteria**: Each rule is installed using both MAC-based (lower priority) and IP-based (higher priority) matching, to ensure correctness across different protocol types.
- Default Rules: Every switch receives an ARP-to-controller rule at the highest priority, and a generic fallback rule at the lowest priority that passes unmatched packets to table 1.
- Dynamic Rule Updates: Topology changes (e.g., switches or links added/removed) trigger a full recomputation and reinstallation of relevant host rules.

Implementation Notes:
---------------------
- Hosts are represented via the Host abstraction provided in the 'edu.brown.cs.sdn.apps.util' package.
- IP and MAC-based rules are installed via the `SwitchCommands.installRule()` utility.
- Logging was used extensively during development to verify Dijkstra path selections and output ports, but unnecessary logging was removed from the final submitted version to comply with style guidelines.

Code Attribution:
-----------------
- We used and extended the `Host` and `SwitchCommands` classes as provided in the 'edu.brown.cs.sdn.apps.util' package.
- The base 'ShortestPathSwitching.java' file was supplied in the starter code. All logic for computing paths, installing/removing rules, and maintaining bidirectional connectivity was implemented as part of this assignment.

Part 4: Distributed Load Balancer
_________________________________

Overview:
---------
The LoadBalancer module implements a distributed, SDN-based load balancer. It handles client requests to a set of virtual IPs and distributes new TCP connections across a list of backend servers in round-robin fashion. The application installs per-connection rules for address rewriting and delegates routing to the SPS module via OpenFlow's multi-table processing.

Key Design Decisions:
---------------------
- Separation of Concerns: Table 0 was used for load balancing logic. Table 1 (used by SPS) was delegated all further forwarding decisions.
- Virtual IP Handling: On receiving ARP requests for a VIP, the controller responds with a generated virtual MAC address for the VIP.
- Connection Mapping: For each new TCP SYN received for a VIP, the controller chooses a backend host and installs two rewrite rules (client→backend and backend→client) with a 20s idle timeout.
- TCP Reset Fallback: If a stale TCP packet arrives for a VIP with no active connection rule, the controller sends a TCP reset to the client to prevent hanging connections.

Implementation Notes:
---------------------
- LoadBalancerInstance handles round-robin selection.
- Connection-specific rules match on IP addresses, transport ports, and protocol.
- Rules use the OpenFlow instruction `goto_table` to pass packets to table 1 after rewriting.
- All logic was placed in the controller; switches remain stateless aside from flow entries.

Code Attribution:
-----------------
- The 'LoadBalancer.java' file was adapted from the starter code provided in the 'finalproject-part4-code.zip'.
- The 'LoadBalancerInstance' class, also provided, was used unmodified for per-VIP host cycling.
- The 'SwitchCommands' and 'MACAddress' utilities were reused from the provided 'edu.brown.cs.sdn.apps.util' package.

Compliance and Documentation Notes
___________________________________

All code modifications and additions were authored by the project submitter unless explicitly attributed above. No external libraries or unapproved packages were used. All functionality complies with the assignment specification, including:

- Use of Dijkstra’s algorithm for shortest-path computation (Part 3).
- Use of OpenFlow multi-table architecture (Part 4).
- All ARP, TCP, and rewrite logic implemented at the controller level.
