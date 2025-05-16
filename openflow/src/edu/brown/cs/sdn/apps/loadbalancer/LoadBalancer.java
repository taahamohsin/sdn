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


public class LoadBalancer implements IFloodlightModule, IOFSwitchListener,
		IOFMessageListener
{
	public static final String MODULE_NAME = LoadBalancer.class.getSimpleName();

	private static final byte TCP_FLAG_SYN = 0x02;

	private static final short IDLE_TIMEOUT = 20;

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

    // Rule 1: Send ARP requests for virtual IPs to controller
    for (Integer vip : this.instances.keySet()) {
        OFMatch matchArp = new OFMatch();
        matchArp.setDataLayerType(Ethernet.TYPE_ARP);
        matchArp.setNetworkDestination(vip);

        List<OFAction> actions = new ArrayList<OFAction>();
        actions.add(new OFActionOutput(OFPort.OFPP_CONTROLLER.getValue()));

        OFInstructionApplyActions instruction = new OFInstructionApplyActions(actions);
        List<OFInstruction> instructions = new ArrayList<OFInstruction>();
        instructions.add(instruction);

        SwitchCommands.installRule(
            sw,
            this.table,
            SwitchCommands.MAX_PRIORITY,
            matchArp,
            instructions
        );
    }

    // Rule 2: Send TCP SYN packets to virtual IPs to controller
    for (Integer vip : this.instances.keySet()) {
        OFMatch matchTcp = new OFMatch();
        matchTcp.setDataLayerType(Ethernet.TYPE_IPv4);
        matchTcp.setNetworkProtocol((byte) 6); // TCP
        matchTcp.setNetworkDestination(vip);
        matchTcp.setTransportDestination((short) 0); // wildcard port
        // NOTE: We cannot match on TCP flags here due to OpenFlow 1.0 limitations.
        // We'll have to filter SYNs in controller receive().

        List<OFAction> actions = new ArrayList<OFAction>();
        actions.add(new OFActionOutput(OFPort.OFPP_CONTROLLER.getValue()));

        OFInstructionApplyActions instruction = new OFInstructionApplyActions(actions);
        List<OFInstruction> instructions = new ArrayList<OFInstruction>();
        instructions.add(instruction);

        SwitchCommands.installRule(
            sw,
            this.table,
            (short) (SwitchCommands.MAX_PRIORITY - 1),
            matchTcp,
            instructions
        );
    }

    // Rule 3: All other packets go to the next table (e.g., ShortestPathSwitching)
    OFMatch matchAll = new OFMatch(); // wildcard match

    List<OFInstruction> gotoNextTable = new ArrayList<OFInstruction>();
    gotoNextTable.add(new org.openflow.protocol.instruction.OFInstructionGotoTable((byte)(this.table + 1)));

    SwitchCommands.installRule(
        sw,
        this.table,
        SwitchCommands.MIN_PRIORITY,
        matchAll,
        gotoNextTable
    );
}


	/**
	 * Handle incoming packets sent from switches.
	 * @param sw switch on which the packet was received
	 * @param msg message from the switch
	 * @param cntx the Floodlight context in which the message should be handled
	 * @return indication whether another module should also process the packet
	 */
	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		if (msg.getType() != OFType.PACKET_IN)
			return Command.CONTINUE;
		OFPacketIn pktIn = (OFPacketIn) msg;

		Ethernet eth = new Ethernet();
		eth.deserialize(pktIn.getPacketData(), 0, pktIn.getPacketData().length);

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
		}

		else if (eth.getEtherType() == Ethernet.TYPE_IPv4) {
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
				log.warn("MAC not known for backend IP " + IPv4.fromIPv4Address(backendIp));
				return Command.STOP;
			}

			if ((tcp.getFlags() & TCP_FLAG_SYN) != 0) {
				// SYN: rewrite destination IP/MAC to backend
				ip.setDestinationAddress(backendIp);
				eth.setDestinationMACAddress(backendMac);
			} else {
				// Other TCP packets: assume response → rewrite source to VIP
				ip.setSourceAddress(dstIp);
				eth.setSourceMACAddress(instance.getVirtualMAC());
			}

			SwitchCommands.sendPacket(sw, (short) pktIn.getInPort(), eth);
			return Command.STOP;
		}

		return Command.CONTINUE;
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
}
