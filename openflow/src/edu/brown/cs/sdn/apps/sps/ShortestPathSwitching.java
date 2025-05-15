package edu.brown.cs.sdn.apps.sps;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;

import edu.brown.cs.sdn.apps.util.Host;
import edu.brown.cs.sdn.apps.util.SwitchCommands;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.routing.Link;


public class ShortestPathSwitching implements IFloodlightModule, IOFSwitchListener,
		ILinkDiscoveryListener, IDeviceListener, InterfaceShortestPathSwitching
{
	public static final String MODULE_NAME = ShortestPathSwitching.class.getSimpleName();

	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);

    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;

    // Interface to link discovery service
    private ILinkDiscoveryService linkDiscProv;

    // Interface to device manager service
    private IDeviceService deviceProv;

    // Switch table in which rules should be installed
    private byte table;

    // Map of hosts to devices
    private Map<IDevice,Host> knownHosts;

	/**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));

		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.linkDiscProv = context.getServiceImpl(ILinkDiscoveryService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);

        this.knownHosts = new ConcurrentHashMap<IDevice,Host>();
	}

    private static String macToString(long mac) {
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
            (mac >> 40) & 0xff,
            (mac >> 32) & 0xff,
            (mac >> 24) & 0xff,
            (mac >> 16) & 0xff,
            (mac >> 8) & 0xff,
            mac & 0xff);
    }

	/**
     * Subscribes to events and performs other startup tasks.
     */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException
	{
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.linkDiscProv.addListener(this);
		this.deviceProv.addListener(this);

		// Install rules for any hosts that already exist
		log.info("Looking for existing hosts...");
		Collection<? extends IDevice> devices = deviceProv.getAllDevices();
		for (IDevice device : devices) {
			Host host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);

			if (host.isAttachedToSwitch()) {
				if (host.getIPv4Address() != null) {
					log.info(String.format("Found existing host %s with IP %s",
						host.getName(), IPv4.fromIPv4Address(host.getIPv4Address())));
				} else {
					log.info(String.format("Found existing host %s with MAC %s (no IP)",
						host.getName(), macToString(host.getMACAddress())));
				}
				installHostRules(host);
			}
		}
	}

	/**
	 * Get the table in which this application installs rules.
	 */
	public byte getTable()
	{ return this.table; }

    /**
     * Get a list of all known hosts in the network.
     */
    private Collection<Host> getHosts()
    { return this.knownHosts.values(); }

    /**
     * Get a map of all active switches in the network. Switch DPID is used as
     * the key.
     */
	private Map<Long, IOFSwitch> getSwitches()
    { return floodlightProv.getAllSwitchMap(); }

    /**
     * Get a list of all active links in the network.
     */
    private Collection<Link> getLinks()
    { return linkDiscProv.getLinks().keySet(); }

    /**
     * Compute the shortest path from a source switch to a destination switch.
     * @param srcSw source switch DPID
     * @param dstSw destination switch DPID
     * @return a map of switch DPIDs to output ports along the path
     */
    private Map<Long, Integer> computeShortestPaths(Long srcSw, Long dstSw)
    {
        Map<Long, Integer> nextHops = new HashMap<Long, Integer>();
        Map<Long, Integer> distances = new HashMap<Long, Integer>();
        Map<Long, Long> predecessors = new HashMap<Long, Long>();
        Set<Long> visited = new HashSet<Long>();
        Queue<Long> queue = new LinkedList<Long>();

        // Initialize distances for all switches to infinity
        for (Long sw : getSwitches().keySet()) {
            distances.put(sw, Integer.MAX_VALUE);
        }

        // Distance to source switch is 0
        distances.put(srcSw, 0);
        queue.add(srcSw);

        // BFS to find shortest paths
        while (!queue.isEmpty()) {
            Long current = queue.poll();
            if (visited.contains(current)) continue;
            visited.add(current);

            // If we've reached the destination, we can stop
            if (current.equals(dstSw)) break;

            // Check all links from the current switch
            for (Link link : getLinks()) {
                Long neighbor = null;
                Integer outPort = null;

                // Link from current switch to neighbor
                if (link.getSrc() == current) {
                    neighbor = link.getDst();
                    outPort = link.getSrcPort();
                }
                // Link from neighbor to current switch
                else if (link.getDst() == current) {
                    neighbor = link.getSrc();
                    outPort = link.getDstPort();
                }
                else {
                    continue; // Link doesn't involve current switch
                }

                // If we haven't visited the neighbor yet
                if (!visited.contains(neighbor)) {
                    int newDist = distances.get(current) + 1;
                    if (newDist < distances.get(neighbor)) {
                        distances.put(neighbor, newDist);
                        predecessors.put(neighbor, current);
                        if (current.equals(srcSw)) {
                            // Direct connection from source
                            nextHops.put(neighbor, outPort);
                        } else {
                            // Propagate next hop from source
                            nextHops.put(neighbor, nextHops.get(current));
                        }
                        queue.add(neighbor);
                    }
                }
            }
        }

        // Build the path from source to destination
        if (predecessors.containsKey(dstSw)) {
            Long current = dstSw;
            while (!current.equals(srcSw)) {
                Long predecessor = predecessors.get(current);

                // Find the link between predecessor and current
                for (Link link : getLinks()) {
                    if ((link.getSrc() == predecessor && link.getDst() == current)) {
                        nextHops.put(predecessor, link.getSrcPort());
                        break;
                    } else if ((link.getDst() == predecessor && link.getSrc() == current)) {
                        nextHops.put(predecessor, link.getDstPort());
                        break;
                    }
                }

                current = predecessor;
            }
        }

        return nextHops;
    }

    /**
     * Install rules to route traffic to a specific host.
     * @param host the host to route traffic to
     * @return true if rules were successfully installed, false otherwise
     */
    private boolean installHostRules(Host host)
    {
        // Skip if host is not attached to a switch
        if (!host.isAttachedToSwitch()) {
            log.warn("Host {} is not attached to a switch, skipping rule installation",
                host.getName());
            return false;
        }

        log.info("Installing rules for host {}", host.getName());

        IOFSwitch hostSwitch = host.getSwitch();
        int hostPort = host.getPort();

        // Convert MAC address from long to byte array
        byte[] macBytes = new byte[6];
        long macAddress = host.getMACAddress();
        for (int i = 5; i >= 0; i--) {
            macBytes[i] = (byte) (macAddress & 0xFF);
            macAddress >>= 8;
        }

        // Create actions for the host's own switch
        List<OFAction> hostActions = new ArrayList<OFAction>();
        hostActions.add(new OFActionOutput((short)hostPort));
        OFInstructionApplyActions hostInstruction = new OFInstructionApplyActions(hostActions);
        List<OFInstruction> hostInstructions = new ArrayList<OFInstruction>();
        hostInstructions.add(hostInstruction);

        boolean success = true;

        // Always install a MAC-only rule (lower priority)
        OFMatch macOnlyMatch = new OFMatch();
        macOnlyMatch.setDataLayerDestination(macBytes);
        log.info(String.format("Installing MAC-only rule for host %s with MAC %s",
            host.getName(), host.getMACAddressString()));

        // Install MAC-only rule on host's own switch
        success &= SwitchCommands.installRule(
            hostSwitch,
            this.table,
            (short)(SwitchCommands.DEFAULT_PRIORITY - 1), // Lower priority
            macOnlyMatch,
            hostInstructions
        );

        if (!success) {
            log.error("Failed to install MAC-only rule for host {} on its own switch", host.getName());
        }

        // If the host has an IP address, also install a higher-priority IP-based rule
        if (host.getIPv4Address() != null) {
            OFMatch ipMatch = new OFMatch();
            ipMatch.setDataLayerType(Ethernet.TYPE_IPv4);
            ipMatch.setNetworkDestination(host.getIPv4Address());
            log.info(String.format("Installing IP-based rule for host %s with IP %s",
                host.getName(), IPv4.fromIPv4Address(host.getIPv4Address())));

            // Install IP-based rule on host's own switch
            success &= SwitchCommands.installRule(
                hostSwitch,
                this.table,
                SwitchCommands.DEFAULT_PRIORITY, // Higher priority
                ipMatch,
                hostInstructions
            );

            if (!success) {
                log.error("Failed to install IP-based rule for host {} on its own switch", host.getName());
            }
        }

        // For all other switches, compute shortest path and install rules
        for (IOFSwitch sw : getSwitches().values()) {
            // Skip the host's own switch (already handled)
            if (sw.getId() == hostSwitch.getId()) continue;

            // Compute shortest path from this switch to the host's switch
            Map<Long, Integer> nextHops = computeShortestPaths(sw.getId(), hostSwitch.getId());

            // If no path exists, skip this switch
            if (!nextHops.containsKey(sw.getId())) {
                log.warn("No path from switch {} to host {}, skipping", sw.getId(), host.getName());
                continue;
            }

            // Get the output port for the next hop
            int outPort = nextHops.get(sw.getId());

            // Create actions to forward to the next hop
            List<OFAction> actions = new ArrayList<OFAction>();
            actions.add(new OFActionOutput((short)outPort));
            OFInstructionApplyActions instruction = new OFInstructionApplyActions(actions);
            List<OFInstruction> instructions = new ArrayList<OFInstruction>();
            instructions.add(instruction);

            log.info("Installing rules for host " + host.getName() +
                    " on switch " + sw.getId() +
                    " outPort=" + outPort);

            // Install MAC-only rule (lower priority)
            success &= SwitchCommands.installRule(
                sw,
                this.table,
                (short)(SwitchCommands.DEFAULT_PRIORITY - 1), // Lower priority
                macOnlyMatch,
                instructions
            );

            if (!success) {
                log.error("Failed to install MAC-only rule for host {} on switch {}", host.getName(), sw.getId());
            }

            // If the host has an IP address, also install a higher-priority IP-based rule
            if (host.getIPv4Address() != null) {
                OFMatch ipMatch = new OFMatch();
                ipMatch.setDataLayerType(Ethernet.TYPE_IPv4);
                ipMatch.setNetworkDestination(host.getIPv4Address());

                // Install IP-based rule
                success &= SwitchCommands.installRule(
                    sw,
                    this.table,
                    SwitchCommands.DEFAULT_PRIORITY, // Higher priority
                    ipMatch,
                    instructions
                );

                if (!success) {
                    log.error("Failed to install IP-based rule for host {} on switch {}", host.getName(), sw.getId());
                }
            }
        }

        return success;
    }

    /**
     * Remove rules for routing traffic to a specific host.
     * @param host the host to remove rules for
     * @return true if rules were successfully removed, false otherwise
     */
    private boolean removeHostRules(Host host)
    {
        log.info("Removing rules for host {}", host.getName());
        boolean success = true;

        // Convert MAC address from long to byte array
        byte[] macBytes = new byte[6];
        long macAddress = host.getMACAddress();
        for (int i = 5; i >= 0; i--) {
            macBytes[i] = (byte) (macAddress & 0xFF);
            macAddress >>= 8;
        }

        // Always remove MAC-only rule
        OFMatch macOnlyMatch = new OFMatch();
        macOnlyMatch.setDataLayerDestination(macBytes);
        log.info(String.format("Removing MAC-only rule for host %s with MAC %s",
            host.getName(), host.getMACAddressString()));

        // Remove MAC-only rules from all switches
        for (IOFSwitch sw : getSwitches().values()) {
            boolean removed = SwitchCommands.removeRules(sw, this.table, macOnlyMatch);
            if (!removed) {
                log.error("Failed to remove MAC-only rule for host {} on switch {}", host.getName(), sw.getId());
                success = false;
            }
        }

        // If the host has an IP address, also remove IP-based rule
        if (host.getIPv4Address() != null) {
            OFMatch ipMatch = new OFMatch();
            ipMatch.setDataLayerType(Ethernet.TYPE_IPv4);
            ipMatch.setNetworkDestination(host.getIPv4Address());
            log.info(String.format("Removing IP-based rule for host %s with IP %s",
                host.getName(), IPv4.fromIPv4Address(host.getIPv4Address())));

            // Remove IP-based rules from all switches
            for (IOFSwitch sw : getSwitches().values()) {
                boolean removed = SwitchCommands.removeRules(sw, this.table, ipMatch);
                if (!removed) {
                    log.error("Failed to remove IP-based rule for host {} on switch {}", host.getName(), sw.getId());
                    success = false;
                }
            }
        }

        return success;
    }

    /**
     * Update routing rules for all hosts.
     * @return true if all rules were successfully updated, false otherwise
     */
    private boolean updateAllHostRules()
    {
        boolean success = true;

        // First, remove all existing rules
        for (Host host : getHosts()) {
            if (!removeHostRules(host)) {
                success = false;
            }
        }

        // Then, install new rules for all hosts
        for (Host host : getHosts()) {
            if (!installHostRules(host)) {
                success = false;
            }
        }

        return success;
    }

    /**
     * Install default rules on a switch:
     * 1. Send ARP packets to the controller (higher priority)
     * 2. Send all other packets to the controller (lowest priority)
     * @param sw the switch to install default rules on
     */
    private void installDefaultRules(IOFSwitch sw)
    {
        // Rule for ARP packets - send to controller only
        OFMatch matchArp = new OFMatch();
        matchArp.setDataLayerType(Ethernet.TYPE_ARP);

        // Send to controller
        OFAction actionArpController = new OFActionOutput(OFPort.OFPP_CONTROLLER.getValue());
        List<OFAction> actionsArp = new ArrayList<OFAction>();
        actionsArp.add(actionArpController);

        OFInstructionApplyActions instructionArp = new OFInstructionApplyActions(actionsArp);
        List<OFInstruction> instructionsArp = new ArrayList<OFInstruction>();
        instructionsArp.add(instructionArp);

        log.info("Installing ARP rule on switch {}: send to controller", sw.getId());
        SwitchCommands.installRule(
            sw,
            this.table,
            (short)(SwitchCommands.DEFAULT_PRIORITY + 1), // Higher priority than default
            matchArp,
            instructionsArp
        );

        // Default rule - send all other packets to controller
        OFMatch matchDefault = new OFMatch();

        OFAction actionDefault = new OFActionOutput(OFPort.OFPP_CONTROLLER.getValue());
        List<OFAction> actionsDefault = new ArrayList<OFAction>();
        actionsDefault.add(actionDefault);

        OFInstructionApplyActions instructionDefault = new OFInstructionApplyActions(actionsDefault);
        List<OFInstruction> instructionsDefault = new ArrayList<OFInstruction>();
        instructionsDefault.add(instructionDefault);

        log.info("Installing default rule on switch {}: send to controller", sw.getId());
        SwitchCommands.installRule(
            sw,
            this.table,
            SwitchCommands.MIN_PRIORITY, // Lowest priority
            matchDefault,
            instructionsDefault
        );
    }

    /**
     * Event handler called when a host joins the network.
     * @param device information about the host
     */
	@Override
	public void deviceAdded(IDevice device)
	{
		Host host = new Host(device, this.floodlightProv);

		// Log all device additions, even if IP is null
		log.info(String.format("Device added: MAC=%s, IP=%s",
			device.getMACAddressString(),
			(host.getIPv4Address() != null) ? IPv4.fromIPv4Address(host.getIPv4Address()) : "null"));

		// Add the host to our known hosts map
		this.knownHosts.put(device, host);

		// If the host is attached to a switch, install rules for it
		if (host.isAttachedToSwitch())
		{
			if (host.getIPv4Address() != null)
			{
				log.info(String.format("Host %s added with IP %s",
					host.getName(), IPv4.fromIPv4Address(host.getIPv4Address())));
			}
			else
			{
				log.info(String.format("Host %s added without IP, installing MAC-based rules",
					host.getName()));
			}

			// Update routing: add rules to route to new host
			boolean success = installHostRules(host);
			log.info(String.format("Rules for host %s %s installed",
				host.getName(), success ? "successfully" : "failed to be"));

			// Install rules for all other hosts too, in case they were missed
			installRulesForAllHosts();
		}
		else
		{
			log.info(String.format("Host %s is not attached to a switch, skipping rule installation",
				host.getName()));
		}
	}

	/**
	 * Install rules for all known hosts.
	 * This ensures we have rules for all hosts, even if some events were missed.
	 */
	private void installRulesForAllHosts()
	{
		log.info("Installing rules for all known hosts");
		for (Host host : getHosts())
		{
			if (host.isAttachedToSwitch())
			{
				if (host.getIPv4Address() != null)
				{
					log.info(String.format("Installing rules for existing host %s with IP %s",
						host.getName(), IPv4.fromIPv4Address(host.getIPv4Address())));
				}
				else
				{
					log.info(String.format("Installing rules for existing host %s with MAC %s (no IP)",
						host.getName(), macToString(host.getMACAddress())));
				}
				installHostRules(host);
			}
		}
	}

	/**
     * Event handler called when a host is no longer attached to a switch.
     * @param device information about the host
     */
	@Override
	public void deviceRemoved(IDevice device)
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}

		log.info(String.format("Host %s is no longer attached to a switch",
				host.getName()));

		// Update routing: remove rules to route to host
		removeHostRules(host);
	}

	/**
     * Event handler called when a host moves within the network.
     * @param device information about the host
     */
	@Override
	public void deviceMoved(IDevice device)
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}

		if (!host.isAttachedToSwitch())
		{
			this.deviceRemoved(device);
			return;
		}
		log.info(String.format("Host %s moved to s%d:%d", host.getName(),
				host.getSwitch().getId(), host.getPort()));

		// Update routing: change rules to route to host
		removeHostRules(host);
		installHostRules(host);
	}

    /**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
	@Override
	public void switchAdded(long switchId)
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d added", switchId));

		// Update routing: change routing rules for all hosts
		installDefaultRules(sw);
		updateAllHostRules();
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId)
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d removed", switchId));

		// Update routing: change routing rules for all hosts
		updateAllHostRules();
	}

	/**
	 * Event handler called when multiple links go up or down.
	 * @param updateList information about the change in each link's state
	 */
	@Override
	public void linkDiscoveryUpdate(List<LDUpdate> updateList)
	{
		for (LDUpdate update : updateList)
		{
			// If we only know the switch & port for one end of the link, then
			// the link must be from a switch to a host
			if (0 == update.getDst())
			{
				log.info(String.format("Link s%s:%d -> host updated",
					update.getSrc(), update.getSrcPort()));
			}
			// Otherwise, the link is between two switches
			else
			{
				log.info(String.format("Link s%s:%d -> %s:%d updated",
					update.getSrc(), update.getSrcPort(),
					update.getDst(), update.getDstPort()));
			}
		}

		// Update routing: change routing rules for all hosts
		updateAllHostRules();
	}

	/**
	 * Event handler called when link goes up or down.
	 * @param update information about the change in link state
	 */
	@Override
	public void linkDiscoveryUpdate(LDUpdate update)
	{ this.linkDiscoveryUpdate(Arrays.asList(update)); }

	/**
     * Event handler called when the IP address of a host changes.
     * @param device information about the host
     */
    @Override
    public void deviceIPV4AddrChanged(IDevice device)
    {
        Host host = new Host(device, this.floodlightProv);
        this.knownHosts.put(device, host);
        if (host.getIPv4Address() != null) {
            log.info("deviceIPV4AddrChanged: Installing rules for " + host.getName());
            installHostRules(host);
        } else {
            log.info("deviceIPV4AddrChanged: IP address still null for " + host.getName());
        }
    }


	/**
     * Event handler called when the VLAN of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceVlanChanged(IDevice device)
	{ /* Nothing we need to do, since we're not using VLANs */ }

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId)
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId)
	{ /* Nothing we need to do */ }

	/**
	 * Event handler called when a port on a switch goes up or down, or is
	 * added or removed.
	 * @param DPID for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type)
	{ /* Nothing we need to do, since we'll get a linkDiscoveryUpdate event */ }

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName()
	{ return this.MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(String type, String name)
	{ return false; }

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(String type, String name)
	{ return false; }

    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices()
	{
		Collection<Class<? extends IFloodlightService>> services =
					new ArrayList<Class<? extends IFloodlightService>>();
		services.add(InterfaceShortestPathSwitching.class);
		return services;
	}

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService>
			getServiceImpls()
	{
        Map<Class<? extends IFloodlightService>, IFloodlightService> services =
        			new HashMap<Class<? extends IFloodlightService>,
        					IFloodlightService>();
        // We are the class that implements the service
        services.put(InterfaceShortestPathSwitching.class, this);
        return services;
	}

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>>
			getModuleDependencies()
	{
		Collection<Class<? extends IFloodlightService >> modules =
	            new ArrayList<Class<? extends IFloodlightService>>();
		modules.add(IFloodlightProviderService.class);
		modules.add(ILinkDiscoveryService.class);
		modules.add(IDeviceService.class);
        return modules;
	}


}
