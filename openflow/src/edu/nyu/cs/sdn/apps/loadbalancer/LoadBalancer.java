package edu.nyu.cs.sdn.apps.loadbalancer;

import java.util.*;

import org.openflow.protocol.*;
import org.openflow.protocol.action.*;
import org.openflow.protocol.instruction.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.nyu.cs.sdn.apps.util.ArpServer;
import edu.nyu.cs.sdn.apps.util.SwitchCommands;

import net.floodlightcontroller.core.*;
import net.floodlightcontroller.core.module.*;
import net.floodlightcontroller.devicemanager.*;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.util.MACAddress;

public class LoadBalancer implements IFloodlightModule, IOFSwitchListener, IOFMessageListener {
	public static final String MODULE_NAME = LoadBalancer.class.getSimpleName();
	private static final byte TCP_FLAG_SYN = 0x02;
	private static final short IDLE_TIMEOUT = 20;
	private static Logger log = LoggerFactory.getLogger(MODULE_NAME);

	private IFloodlightProviderService floodlightProv;
	private IDeviceService deviceProv;
	private byte table;
	private Map<Integer, LoadBalancerInstance> instances;

	// Initialize config and parse VIP mappings
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		log.info("Initializing " + MODULE_NAME);
		this.instances = new HashMap<Integer, LoadBalancerInstance>();
		Map<String, String> config = context.getConfigParams(this);
		this.table = Byte.parseByte(config.get("table"));
		String[] instanceConfigs = config.get("instances").split(";");
		for (String configStr : instanceConfigs) {
			String[] items = configStr.trim().split(" ");
			if (items.length == 3) {
				LoadBalancerInstance instance = new LoadBalancerInstance(items[0], items[1], items[2].split(","));
				this.instances.put(instance.getVirtualIP(), instance);
			}
		}
		this.floodlightProv = context.getServiceImpl(IFloodlightProviderService.class);
		this.deviceProv = context.getServiceImpl(IDeviceService.class);
	}

	// Register controller callbacks
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProv.addOFSwitchListener(this);
		floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);
	}

	// Install default controller-forwarding rules for ARP and TCP to VIP
	public void switchAdded(long switchId) {
		IOFSwitch sw = floodlightProv.getSwitch(switchId);
		if (sw == null)
			return;
		for (LoadBalancerInstance instance : instances.values()) {
			int vip = instance.getVirtualIP();

			// Forward ARP for VIP to controller
			OFMatch arpMatch = new OFMatch();
			arpMatch.setDataLayerType(Ethernet.TYPE_ARP);
			arpMatch.setNetworkDestination(vip);
			SwitchCommands.installRule(sw, this.table, (short) (SwitchCommands.DEFAULT_PRIORITY + 1), arpMatch,
					buildControllerForwardInstr(), (short) 0, (short) 0);

			// Forward TCP to VIP to controller
			OFMatch tcpMatch = new OFMatch();
			tcpMatch.setDataLayerType(Ethernet.TYPE_IPv4);
			tcpMatch.setNetworkProtocol(IPv4.PROTOCOL_TCP);
			tcpMatch.setNetworkDestination(vip);
			SwitchCommands.installRule(sw, this.table, (short) (SwitchCommands.DEFAULT_PRIORITY + 1), tcpMatch,
					buildControllerForwardInstr(), (short) 0, (short) 0);

			OFMatch fallbackMatch = new OFMatch();
			List<OFInstruction> gotoInstr = new ArrayList<OFInstruction>();
			gotoInstr.add(new OFInstructionGotoTable((byte) 1));
			SwitchCommands.installRule(sw, this.table, SwitchCommands.DEFAULT_PRIORITY, fallbackMatch, gotoInstr, (short) 0,
					(short) 0);

			OFMatch icmpMatch = new OFMatch();
			icmpMatch.setDataLayerType(Ethernet.TYPE_IPv4);
			icmpMatch.setNetworkProtocol(IPv4.PROTOCOL_ICMP);

			List<OFInstruction> icmpInstr = new ArrayList<OFInstruction>();
			icmpInstr.add(new OFInstructionGotoTable((byte) 1));

			SwitchCommands.installRule(
					sw,
					this.table,
					(short) (SwitchCommands.DEFAULT_PRIORITY + 1),
					icmpMatch,
					icmpInstr,
					(short) 0,
					(short) 0);

		}
	}

	// Handle incoming packets
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		if (msg.getType() != OFType.PACKET_IN)
			return Command.CONTINUE;
		OFPacketIn pktIn = (OFPacketIn) msg;
		Ethernet eth = new Ethernet();
		eth.deserialize(pktIn.getPacketData(), 0, pktIn.getPacketData().length);

		// Respond to ARP requests for VIP
		if (eth.getEtherType() == Ethernet.TYPE_ARP && eth.getPayload() instanceof ARP) {
			ARP arp = (ARP) eth.getPayload();
			int vip = IPv4.toIPv4Address(arp.getTargetProtocolAddress());
			LoadBalancerInstance instance = instances.get(vip);
			if (instance != null) {
				Ethernet arpReply = createArpReply(eth, arp, instance);
				SwitchCommands.sendPacket(sw, (short) pktIn.getInPort(), arpReply);
				return Command.STOP;
			}
		}

		// Handle TCP connection establishment
		if (eth.getEtherType() == Ethernet.TYPE_IPv4 && eth.getPayload() instanceof IPv4) {
			IPv4 ip = (IPv4) eth.getPayload();
			if (ip.getProtocol() == IPv4.PROTOCOL_TCP && ip.getPayload() instanceof TCP) {
				TCP tcp = (TCP) ip.getPayload();
				int vip = ip.getDestinationAddress();
				LoadBalancerInstance instance = instances.get(vip);
				if (instance != null) {
					if ((tcp.getFlags() & TCP_FLAG_SYN) != 0) {
						// Assign backend
						int backendIP = instance.getNextHostIP();
						byte[] backendMAC = getHostMACAddress(backendIP);
						if (backendMAC == null)
							return Command.CONTINUE;

						// Match flow from client to VIP
						int clientIP = ip.getSourceAddress();
						short clientPort = tcp.getSourcePort();
						short vipPort = tcp.getDestinationPort();

						OFMatch c2s = new OFMatch();
						c2s.setDataLayerType(Ethernet.TYPE_IPv4);
						c2s.setNetworkProtocol(IPv4.PROTOCOL_TCP);
						c2s.setNetworkSource(clientIP);
						c2s.setNetworkDestination(vip);
						c2s.setTransportSource(clientPort);
						c2s.setTransportDestination(vipPort);

						// Rewrite destination to backend
						List<OFInstruction> c2sInstr = new ArrayList<OFInstruction>();
						List<OFAction> c2sActions = new ArrayList<OFAction>();
						c2sActions.add(new OFActionSetField(OFOXMFieldType.ETH_DST, backendMAC));
						c2sActions.add(new OFActionSetField(OFOXMFieldType.IPV4_DST, backendIP));
						c2sInstr.add(new OFInstructionApplyActions(c2sActions));
						c2sInstr.add(new OFInstructionGotoTable((byte) 1));
						SwitchCommands.installRule(sw, this.table, (short) (SwitchCommands.DEFAULT_PRIORITY + 2), c2s, c2sInstr,
								IDLE_TIMEOUT, IDLE_TIMEOUT);

						// Rewrite response from backend to client
						OFMatch s2c = new OFMatch();
						s2c.setDataLayerType(Ethernet.TYPE_IPv4);
						s2c.setNetworkProtocol(IPv4.PROTOCOL_TCP);
						s2c.setNetworkSource(backendIP);
						s2c.setNetworkDestination(clientIP);
						s2c.setTransportSource(vipPort);
						s2c.setTransportDestination(clientPort);

						List<OFInstruction> s2cInstr = new ArrayList<OFInstruction>();
						List<OFAction> s2cActions = new ArrayList<OFAction>();
						s2cActions.add(new OFActionSetField(OFOXMFieldType.IPV4_SRC, vip));
						s2cInstr.add(new OFInstructionApplyActions(s2cActions));
						s2cInstr.add(new OFInstructionGotoTable((byte) 1));

						SwitchCommands.installRule(sw, this.table, (short) (SwitchCommands.DEFAULT_PRIORITY + 2), s2c, s2cInstr,
								IDLE_TIMEOUT, IDLE_TIMEOUT);
						return Command.STOP;
					} else {
						// Not a SYN: reset connection
						SwitchCommands.sendPacket(sw, (short) pktIn.getInPort(), createTcpReset(eth));
						return Command.STOP;
					}
				}
			}
		}
		return Command.CONTINUE;
	}

	// Construct ARP reply for VIP
	private Ethernet createArpReply(Ethernet eth, ARP arp, LoadBalancerInstance instance) {
		Ethernet arpReply = new Ethernet();
		arpReply.setSourceMACAddress(instance.getVirtualMAC());
		arpReply.setDestinationMACAddress(eth.getSourceMACAddress());
		arpReply.setEtherType(Ethernet.TYPE_ARP);
		ARP payload = new ARP();
		payload.setHardwareType(ARP.HW_TYPE_ETHERNET);
		payload.setProtocolType(ARP.PROTO_TYPE_IP);
		payload.setOpCode(ARP.OP_REPLY);
		payload.setHardwareAddressLength((byte) 6);
		payload.setProtocolAddressLength((byte) 4);
		payload.setSenderHardwareAddress(instance.getVirtualMAC());
		payload.setSenderProtocolAddress(arp.getTargetProtocolAddress());
		payload.setTargetHardwareAddress(arp.getSenderHardwareAddress());
		payload.setTargetProtocolAddress(arp.getSenderProtocolAddress());
		arpReply.setPayload(payload);
		return arpReply;
	}

	// Construct TCP reset for non-SYN packets to VIP
	private Ethernet createTcpReset(Ethernet eth) {
		IPv4 ip = (IPv4) eth.getPayload();
		TCP origTcp = (TCP) ip.getPayload();
		TCP rst = new TCP();
		rst.setSourcePort(origTcp.getDestinationPort());
		rst.setDestinationPort(origTcp.getSourcePort());
		rst.setFlags((byte) 0x14);
		rst.setSequence(origTcp.getAcknowledge());
		rst.setAcknowledge(origTcp.getSequence() + 1);
		IPv4 ipPkt = new IPv4();
		ipPkt.setTtl((byte) 64);
		ipPkt.setProtocol(IPv4.PROTOCOL_TCP);
		ipPkt.setSourceAddress(ip.getDestinationAddress());
		ipPkt.setDestinationAddress(ip.getSourceAddress());
		ipPkt.setPayload(rst);
		Ethernet ethPkt = new Ethernet();
		ethPkt.setEtherType(Ethernet.TYPE_IPv4);
		ethPkt.setSourceMACAddress(eth.getDestinationMACAddress());
		ethPkt.setDestinationMACAddress(eth.getSourceMACAddress());
		ethPkt.setPayload(ipPkt);
		return ethPkt;
	}

	// Generate controller-forwarding instruction block
	private List<OFInstruction> buildControllerForwardInstr() {
		List<OFAction> actions = new ArrayList<OFAction>();
		actions.add(new OFActionOutput(OFPort.OFPP_CONTROLLER.getValue()));
		List<OFInstruction> instructions = new ArrayList<OFInstruction>();
		instructions.add(new OFInstructionApplyActions(actions));
		return instructions;
	}

	// Look up MAC for backend IP
	private byte[] getHostMACAddress(int hostIPAddress) {
		Iterator<? extends IDevice> it = deviceProv.queryDevices(null, null, hostIPAddress, null, null);
		if (it.hasNext())
			return MACAddress.valueOf(it.next().getMACAddress()).toBytes();
		return null;
	}

	// Unused listener methods
	public void switchRemoved(long id) {
	}

	public void switchActivated(long id) {
	}

	public void switchChanged(long id) {
	}

	public void switchPortChanged(long switchId, ImmutablePort port, IOFSwitch.PortChangeType type) {
	}

	public String getName() {
		return MODULE_NAME;
	}

	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return OFType.PACKET_IN == type &&
				(name.equals(ArpServer.MODULE_NAME) || name.equals(DeviceManagerImpl.MODULE_NAME));
	}

	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> deps = new ArrayList<Class<? extends IFloodlightService>>();
		deps.add(IFloodlightProviderService.class);
		deps.add(IDeviceService.class);
		return deps;
	}
}
