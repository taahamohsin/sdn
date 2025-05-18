package edu.nyu.cs.sdn.apps.loadbalancer;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.List;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.instruction.OFInstructionGotoTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.nyu.cs.sdn.apps.util.SwitchCommands;
import edu.nyu.cs.sdn.apps.util.ArpServer;

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
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.Data;
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

	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		log.info("Initializing " + MODULE_NAME);
		this.instances = new HashMap<Integer, LoadBalancerInstance>();

		Map<String, String> config = context.getConfigParams(this);
		this.table = Byte.parseByte(config.get("table"));

		String[] instanceConfigs = config.get("instances").split(";");
		for (int i = 0; i < instanceConfigs.length; i++) {
			String[] items = instanceConfigs[i].trim().split(" ");
			if (items.length != 3)
				continue;
			LoadBalancerInstance instance = new LoadBalancerInstance(items[0], items[1], items[2].split(","));
			this.instances.put(instance.getVirtualIP(), instance);
		}

		this.floodlightProv = context.getServiceImpl(IFloodlightProviderService.class);
		this.deviceProv = context.getServiceImpl(IDeviceService.class);
	}

	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProv.addOFSwitchListener(this);
		floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);
	}

@Override
public void switchAdded(long switchId) {
    IOFSwitch sw = floodlightProv.getSwitch(switchId);

    for (LoadBalancerInstance instance : instances.values()) {
        // --- ARP Matching Rule ---
        OFMatch arpMatch = new OFMatch();
        arpMatch.setDataLayerType(Ethernet.TYPE_ARP);
        arpMatch.setNetworkDestination(instance.getVirtualIP());

        List<OFAction> arpActions = new ArrayList<OFAction>();
        arpActions.add(new OFActionOutput((short) 0xfffd)); // OFPP_CONTROLLER

        List<OFInstruction> arpInstructions = new ArrayList<OFInstruction>();
        arpInstructions.add(new OFInstructionApplyActions(arpActions));

        SwitchCommands.installRule(
            sw,
            this.table,
            (short) (SwitchCommands.DEFAULT_PRIORITY + 1),
            arpMatch,
            arpInstructions
        );

        // --- IPv4 Matching Rule ---
        OFMatch ipMatch = new OFMatch();
        ipMatch.setDataLayerType(Ethernet.TYPE_IPv4);
        ipMatch.setNetworkDestination(instance.getVirtualIP());

        List<OFAction> ipActions = new ArrayList<OFAction>();
        ipActions.add(new OFActionOutput((short) 0xfffd)); // OFPP_CONTROLLER

        List<OFInstruction> ipInstructions = new ArrayList<OFInstruction>();
        ipInstructions.add(new OFInstructionApplyActions(ipActions));

        SwitchCommands.installRule(
            sw,
            this.table,
            (short) (SwitchCommands.DEFAULT_PRIORITY + 1),
            ipMatch,
            ipInstructions
        );
    }

    // --- Table Miss Entry: Go to next table ---
    List<OFInstruction> missInstructions = new ArrayList<OFInstruction>();
    missInstructions.add(new OFInstructionGotoTable((byte) (this.table + 1)));

    OFMatch matchAll = new OFMatch(); // Match everything (table miss)
    SwitchCommands.installRule(
        sw,
        this.table,
        SwitchCommands.DEFAULT_PRIORITY,
        matchAll,
        missInstructions
    );
}


	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		if (msg.getType() != OFType.PACKET_IN)
			return Command.CONTINUE;
		OFPacketIn pktIn = (OFPacketIn) msg;
		Ethernet eth = new Ethernet();
		eth.deserialize(pktIn.getPacketData(), 0, pktIn.getPacketData().length);

		if (eth.getEtherType() == Ethernet.TYPE_ARP) {
			ARP arp = (ARP) eth.getPayload();
			int targetIP = IPv4.toIPv4Address(arp.getTargetProtocolAddress());
			LoadBalancerInstance instance = instances.get(targetIP);
			if (instance != null) {
				Ethernet arpReply = new Ethernet();
				arpReply.setSourceMACAddress(instance.getVirtualMAC());
				arpReply.setDestinationMACAddress(eth.getSourceMACAddress());
				arpReply.setEtherType(Ethernet.TYPE_ARP);

				ARP arpPayload = new ARP();
				arpPayload.setHardwareType(ARP.HW_TYPE_ETHERNET);
				arpPayload.setProtocolType(ARP.PROTO_TYPE_IP);
				arpPayload.setOpCode(ARP.OP_REPLY);
				arpPayload.setHardwareAddressLength((byte) 6);
				arpPayload.setProtocolAddressLength((byte) 4);
				arpPayload.setSenderHardwareAddress(instance.getVirtualMAC());
				arpPayload.setSenderProtocolAddress(arp.getTargetProtocolAddress());
				arpPayload.setTargetHardwareAddress(arp.getSenderHardwareAddress());
				arpPayload.setTargetProtocolAddress(arp.getSenderProtocolAddress());
				arpReply.setPayload(arpPayload);

				SwitchCommands.sendPacket(sw, (short) pktIn.getInPort(), arpReply);
				return Command.STOP;
			}
		}

		return Command.CONTINUE;
	}

	private byte[] getHostMACAddress(int hostIPAddress) {
		Iterator<? extends IDevice> it = deviceProv.queryDevices(null, null, hostIPAddress, null, null);
		if (it.hasNext()) {
			return MACAddress.valueOf(it.next().getMACAddress()).toBytes();
		}
		return null;
	}

	public void switchRemoved(long switchId) {
	}

	public void switchActivated(long switchId) {
	}

	public void switchPortChanged(long switchId, ImmutablePort port, PortChangeType type) {
	}

	public void switchChanged(long switchId) {
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
