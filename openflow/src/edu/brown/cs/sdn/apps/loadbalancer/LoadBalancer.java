package edu.brown.cs.sdn.apps.loadbalancer;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.List;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.brown.cs.sdn.apps.util.ArpServer;
import edu.brown.cs.sdn.apps.util.SwitchCommands;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.util.MACAddress;
import net.floodlightcontroller.packet.TCP;

import org.openflow.protocol.instruction.OFInstructionGotoTable;

public class LoadBalancer implements IFloodlightModule, IOFSwitchListener,
		IOFMessageListener
{
	static {
		System.out.println("LoadBalancerApp loaded!");
	}

	public static final String MODULE_NAME = LoadBalancer.class.getSimpleName();

	private static final byte TCP_FLAG_SYN = 0x02;

	private static final short IDLE_TIMEOUT = 20;

	private static final byte TCP_FLAG_RST = 0x04
	;
	private static final byte TCP_FLAG_ACK = 0x10;

	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);

    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;

    // Interface to device manager service
    private IDeviceService deviceProv;

    // Interface to L3Routing application
    // private IL3Routing l3RoutingApp;

    // Switch table in which rules should be installed
    private byte table;

    // Set of virtual IPs and the load balancer instances they correspond with
    private Map<Integer,LoadBalancerInstance> instances;

    /**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));

		// Obtain table number from config
		Map<String,String> config = context.getConfigParams(this);
    this.table = Byte.parseByte(config.get("table"));

		// Create instances from config
		this.instances = new HashMap<Integer,LoadBalancerInstance>();
		String[] instanceConfigs = config.get("instances").split(";");
		for (String instanceConfig : instanceConfigs)
		{
			String[] configItems = instanceConfig.split(" ");
			if (configItems.length != 3)
			{
				log.error("Ignoring bad instance config: " + instanceConfig);
				continue;
			}
			LoadBalancerInstance instance = new LoadBalancerInstance(
					configItems[0], configItems[1], configItems[2].split(","));
				this.instances.put(instance.getVirtualIP(), instance);
				log.info("Added load balancer instance: " + instance);
		}

		this.floodlightProv = context.getServiceImpl(
				IFloodlightProviderService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);

        // this.l3RoutingApp = context.getServiceImpl(IL3Routing.class);

        /*********************************************************************/
        /* TODO: Initialize other class variables, if necessary              */

        /*********************************************************************/
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
		this.floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);
		log.info("Load balancer initialized with " + this.instances.size() + " virtual IP(s).");

		/*********************************************************************/
		/* TODO: Perform other tasks, if necessary                           */

		/*********************************************************************/
	}

	/**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
		@Override
		public void switchAdded(long switchId) {
			IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
			log.info(String.format("Switch s%d added", switchId));

			for (Integer vip : this.instances.keySet()) {
				System.out.println("Installing ARP rule for VIP: " + IPv4.fromIPv4Address(vip));
				System.out.println("Installing TCP rule for VIP: " + IPv4.fromIPv4Address(vip));

				// ARP packets → controller (match *all* ARP requests, not filtered by IP)
				OFMatch matchArp = new OFMatch();
				matchArp.setDataLayerType(Ethernet.TYPE_ARP); // DO NOT setNetworkDestination()

				List<OFAction> arpActions = new ArrayList<OFAction>();
				arpActions.add(new OFActionOutput(OFPort.OFPP_CONTROLLER.getValue()));

				List<OFInstruction> arpInstrs = new ArrayList<OFInstruction>();
				arpInstrs.add(new OFInstructionApplyActions(arpActions));

				SwitchCommands.installRule(sw, this.table, SwitchCommands.MAX_PRIORITY, matchArp, arpInstrs);

				// TCP to VIP → controller (correct as-is)
				OFMatch matchTcp = new OFMatch();
				matchTcp.setDataLayerType(Ethernet.TYPE_IPv4);
				matchTcp.setNetworkProtocol(IPv4.PROTOCOL_TCP);
				matchTcp.setNetworkDestination(vip);

				List<OFAction> tcpActions = new ArrayList<OFAction>();
				tcpActions.add(new OFActionOutput(OFPort.OFPP_CONTROLLER.getValue()));

				List<OFInstruction> tcpInstrs = new ArrayList<OFInstruction>();
				tcpInstrs.add(new OFInstructionApplyActions(tcpActions));

				SwitchCommands.installRule(sw, this.table, (short) (SwitchCommands.MAX_PRIORITY - 1), matchTcp, tcpInstrs);
			}

		// Default fallthrough rule to forward to table 1 (ShortestPathSwitching)
		OFMatch matchAll = new OFMatch();
		List<OFInstruction> passInstrs = new ArrayList<OFInstruction>();
		passInstrs.add(new OFInstructionGotoTable((byte) (this.table + 1)));
		SwitchCommands.installRule(sw, this.table, SwitchCommands.MIN_PRIORITY, matchAll, passInstrs);
	}



	private void installConnectionRules(IOFSwitch sw,
			int clientIp,
			int vip,
			int backendIp,
			short clientPort,
			short vipPort) {

		// Rule 1: client → VIP
		OFMatch matchToBackend = new OFMatch();
		matchToBackend.setDataLayerType(Ethernet.TYPE_IPv4);
		matchToBackend.setNetworkProtocol(IPv4.PROTOCOL_TCP);
		matchToBackend.setNetworkSource(clientIp);
		matchToBackend.setNetworkDestination(vip);
		matchToBackend.setTransportSource(clientPort);
		matchToBackend.setTransportDestination(vipPort);

		List<OFInstruction> instrsToBackend = new ArrayList<OFInstruction>();
		instrsToBackend.add(new OFInstructionApplyActions(new ArrayList<OFAction>()));

		SwitchCommands.installRule(sw,
				this.table,
				SwitchCommands.MAX_PRIORITY,
				matchToBackend,
				instrsToBackend,
				(short) 0, // hardTimeout
				IDLE_TIMEOUT);

		// Rule 2: backend → client
		OFMatch matchToClient = new OFMatch();
		matchToClient.setDataLayerType(Ethernet.TYPE_IPv4);
		matchToClient.setNetworkProtocol(IPv4.PROTOCOL_TCP);
		matchToClient.setNetworkSource(backendIp);
		matchToClient.setNetworkDestination(clientIp);
		matchToClient.setTransportSource(vipPort);
		matchToClient.setTransportDestination(clientPort);

		List<OFInstruction> instrsToClient = new ArrayList<OFInstruction>();
		instrsToClient.add(new OFInstructionApplyActions(new ArrayList<OFAction>()));

		SwitchCommands.installRule(sw,
				this.table,
				SwitchCommands.MAX_PRIORITY,
				matchToClient,
				instrsToClient,
				(short) 0, // hardTimeout
				IDLE_TIMEOUT);
	}

	private void sendTcpReset(IOFSwitch sw, short inPort, Ethernet originalEth, IPv4 originalIp, TCP originalTcp) {
		// Build TCP RST
		TCP tcpReset = new TCP();
		tcpReset.setSourcePort(originalTcp.getDestinationPort());
		tcpReset.setDestinationPort(originalTcp.getSourcePort());
		tcpReset.setFlags((short) (TCP_FLAG_RST | TCP_FLAG_ACK));
		tcpReset.setSequence(originalTcp.getAcknowledge());
		tcpReset.setAcknowledge(originalTcp.getSequence() + 1);

		// Build IPv4
		IPv4 ip = new IPv4();
		ip.setTtl((byte) 64);
		ip.setProtocol(IPv4.PROTOCOL_TCP);
		ip.setSourceAddress(originalIp.getDestinationAddress());
		ip.setDestinationAddress(originalIp.getSourceAddress());
		ip.setPayload(tcpReset);

		// Build Ethernet
		Ethernet eth = new Ethernet();
		eth.setEtherType(Ethernet.TYPE_IPv4);
		eth.setSourceMACAddress(originalEth.getDestinationMACAddress());
		eth.setDestinationMACAddress(originalEth.getSourceMACAddress());
		eth.setPayload(ip);

		// Send packet out
		SwitchCommands.sendPacket(sw, inPort, eth);
	}


	/**
	 * Returns the MAC address for a host, given the host's IP address.
	 * @param hostIPAddress the host's IP address
	 * @return the hosts's MAC address, null if unknown
	 */
	private byte[] getHostMACAddress(int hostIPAddress)
	{
		Iterator<? extends IDevice> iterator = this.deviceProv.queryDevices(
				null, null, hostIPAddress, null, null);
		if (!iterator.hasNext())
		{ return null; }
		IDevice device = iterator.next();
		return MACAddress.valueOf(device.getMACAddress()).toBytes();
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId)
	{ /* Nothing we need to do, since the switch is no longer active */ }

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId)
	{ /* Nothing we need to do, since we're not switching controller roles */ }

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
	{ /* Nothing we need to do, since load balancer rules are port-agnostic */}

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId)
	{ /* Nothing we need to do */ }

    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices()
	{ return null; }

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService>
			getServiceImpls()
	{ return null; }

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>>
			getModuleDependencies()
	{
		Collection<Class<? extends IFloodlightService >> floodlightService =
	            new ArrayList<Class<? extends IFloodlightService>>();
        floodlightService.add(IFloodlightProviderService.class);
        floodlightService.add(IDeviceService.class);
        return floodlightService;
	}

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName()
	{ return MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name)
	{
		return (OFType.PACKET_IN == type
				&& (name.equals(ArpServer.MODULE_NAME)
					|| name.equals(DeviceManagerImpl.MODULE_NAME)));
	}

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name)
	{ return false; }

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		System.out.println("PacketIn received");
		if (msg.getType() != OFType.PACKET_IN)
			return Command.CONTINUE;

		OFPacketIn pktIn = (OFPacketIn) msg;

		Ethernet eth = new Ethernet();
		eth.deserialize(pktIn.getPacketData(), 0, pktIn.getPacketData().length);

		// ARP Handling
		if (eth.getEtherType() == Ethernet.TYPE_ARP) {
			ARP arp = (ARP) eth.getPayload();
			int targetIp = IPv4.toIPv4Address(arp.getTargetProtocolAddress());

			if (this.instances.containsKey(targetIp)) {
				LoadBalancerInstance instance = this.instances.get(targetIp);
				byte[] vipMac = instance.getVirtualMAC();

				Ethernet ethReply = new Ethernet();
				ethReply.setSourceMACAddress(vipMac);
				ethReply.setDestinationMACAddress(eth.getSourceMACAddress());
				ethReply.setEtherType(Ethernet.TYPE_ARP);

				ARP arpReply = new ARP();
				arpReply.setHardwareType(ARP.HW_TYPE_ETHERNET);
				arpReply.setProtocolType(ARP.PROTO_TYPE_IP);
				arpReply.setHardwareAddressLength((byte) 6);
				arpReply.setProtocolAddressLength((byte) 4);
				arpReply.setOpCode(ARP.OP_REPLY);
				arpReply.setSenderHardwareAddress(vipMac);
				arpReply.setSenderProtocolAddress(targetIp);
				arpReply.setTargetHardwareAddress(arp.getSenderHardwareAddress());
				arpReply.setTargetProtocolAddress(arp.getSenderProtocolAddress());

				ethReply.setPayload(arpReply);
				SwitchCommands.sendPacket(sw, (short) pktIn.getInPort(), ethReply);
				return Command.STOP;
			}

			return Command.CONTINUE;
		}

		// TCP Handling
		if (eth.getEtherType() == Ethernet.TYPE_IPv4) {
			IPv4 ip = (IPv4) eth.getPayload();
			if (ip.getProtocol() != IPv4.PROTOCOL_TCP)
				return Command.CONTINUE;

			TCP tcp = (TCP) ip.getPayload();
			int dstIp = ip.getDestinationAddress();

			if (!this.instances.containsKey(dstIp))
				return Command.CONTINUE;

			LoadBalancerInstance instance = this.instances.get(dstIp);
			int backendIp = instance.getNextHostIP();
			byte[] backendMac = getHostMACAddress(backendIp);
			if (backendMac == null) {
				log.warn("Unknown MAC for backend IP: " + IPv4.fromIPv4Address(backendIp));
				return Command.STOP;
			}

			if ((tcp.getFlags() & TCP_FLAG_SYN) != 0) {
				// Handle new connection
				ip.setDestinationAddress(backendIp);
				eth.setDestinationMACAddress(backendMac);

				// Forward modified SYN to backend
				SwitchCommands.sendPacket(sw, (short) pktIn.getInPort(), eth);

				// Install passthrough rules
				installConnectionRules(
						sw,
						ip.getSourceAddress(),
						dstIp, // VIP
						backendIp,
						tcp.getSourcePort(),
						tcp.getDestinationPort());

				return Command.STOP;
			} else {
				// Non-SYN to VIP: must be stale or invalid
				sendTcpReset(sw, (short) pktIn.getInPort(), eth, ip, tcp);
				return Command.STOP;
			}
		}

		return Command.CONTINUE;
	}

}
