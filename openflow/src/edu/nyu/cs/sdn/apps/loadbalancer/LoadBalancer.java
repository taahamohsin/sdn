
package edu.wisc.cs.sdn.apps.loadbalancer;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.openflow.protocol.OFFlowMod;
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

import edu.wisc.cs.sdn.apps.util.SwitchCommands;
import edu.wisc.cs.sdn.apps.util.ArpServer;

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

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        log.info(String.format("Initializing %s...", MODULE_NAME));

        Map<String, String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        this.instances = new HashMap<>();

        String[] instanceConfigs = config.get("instances").split(";");
        for (String instanceConfig : instanceConfigs) {
            String[] items = instanceConfig.trim().split(" ");
            if (items.length != 3) continue;
            LoadBalancerInstance instance = new LoadBalancerInstance(items[0], items[1], items[2].split(","));
            this.instances.put(instance.getVirtualIP(), instance);
        }

        this.floodlightProv = context.getServiceImpl(IFloodlightProviderService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        log.info(String.format("Starting %s...", MODULE_NAME));
        floodlightProv.addOFSwitchListener(this);
        floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);
    }

    @Override
    public void switchAdded(long switchId) {
        IOFSwitch sw = floodlightProv.getSwitch(switchId);

        for (LoadBalancerInstance instance : instances.values()) {
            SwitchCommands.installPacketRule(sw, this.table, SwitchCommands.DEFAULT_PRIORITY + 1,
                    Ethernet.TYPE_ARP, instance.getVirtualIP(), SwitchCommands.ANY, SwitchCommands.CONTROLLER);

            SwitchCommands.installPacketRule(sw, this.table, SwitchCommands.DEFAULT_PRIORITY + 1,
                    Ethernet.TYPE_IPv4, instance.getVirtualIP(), SwitchCommands.ANY, SwitchCommands.CONTROLLER);
        }

        SwitchCommands.installTableMissEntry(sw, this.table, SwitchCommands.DEFAULT_PRIORITY,
                new OFInstructionGotoTable((byte)(this.table + 1)));
    }

    @Override
    public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        if (msg.getType() != OFType.PACKET_IN) return Command.CONTINUE;
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

        if (eth.getEtherType() == Ethernet.TYPE_IPv4 && eth.getPayload() instanceof IPv4) {
            IPv4 ip = (IPv4) eth.getPayload();
            if (ip.getProtocol() == IPv4.PROTOCOL_TCP && ip.getPayload() instanceof TCP) {
                TCP tcp = (TCP) ip.getPayload();
                int dstIP = ip.getDestinationAddress();
                LoadBalancerInstance instance = instances.get(dstIP);

                if (instance != null) {
                    if ((tcp.getFlags() & TCP_FLAG_SYN) != 0) {
                        int backendIP = instance.getNextHostIP();
                        byte[] backendMAC = getHostMACAddress(backendIP);
                        if (backendMAC == null) return Command.CONTINUE;

                        int srcIP = ip.getSourceAddress();
                        short srcPort = tcp.getSourcePort();
                        short dstPort = tcp.getDestinationPort();

                        // Client to Server
                        OFMatch match1 = new OFMatch();
                        match1.setDataLayerType(Ethernet.TYPE_IPv4);
                        match1.setNetworkProtocol(IPv4.PROTOCOL_TCP);
                        match1.setNetworkSource(srcIP);
                        match1.setNetworkDestination(dstIP);
                        match1.setTransportSource(srcPort);
                        match1.setTransportDestination(dstPort);

                        OFAction setDstIP = new OFActionSetField(OFOXMFieldType.IPV4_DST, backendIP);
                        OFAction setDstMAC = new OFActionSetField(OFOXMFieldType.ETH_DST, backendMAC);
                        OFInstructionApplyActions apply1 = new OFInstructionApplyActions(List.of(setDstIP, setDstMAC));
                        SwitchCommands.installRule(sw, this.table, SwitchCommands.DEFAULT_PRIORITY + 2, match1,
                                List.of(apply1), IDLE_TIMEOUT);

                        // Server to Client
                        OFMatch match2 = new OFMatch();
                        match2.setDataLayerType(Ethernet.TYPE_IPv4);
                        match2.setNetworkProtocol(IPv4.PROTOCOL_TCP);
                        match2.setNetworkSource(backendIP);
                        match2.setNetworkDestination(srcIP);
                        match2.setTransportSource(dstPort);
                        match2.setTransportDestination(srcPort);

                        OFAction setSrcIP = new OFActionSetField(OFOXMFieldType.IPV4_SRC, dstIP);
                        OFAction setSrcMAC = new OFActionSetField(OFOXMFieldType.ETH_SRC, instance.getVirtualMAC());
                        OFInstructionApplyActions apply2 = new OFInstructionApplyActions(List.of(setSrcIP, setSrcMAC));
                        SwitchCommands.installRule(sw, this.table, SwitchCommands.DEFAULT_PRIORITY + 2, match2,
                                List.of(apply2), IDLE_TIMEOUT);

                        return Command.STOP;
                    } else {
                        Ethernet rstPkt = (Ethernet) eth.clone();
                        IPv4 ipPayload = (IPv4) rstPkt.getPayload();
                        TCP tcpPayload = (TCP) ipPayload.getPayload();
                        tcpPayload.setFlags((short) 0x014); // ACK + RST
                        tcpPayload.setPayload(new Data(new byte[0]));
                        ipPayload.setPayload(tcpPayload);
                        rstPkt.setPayload(ipPayload);

                        SwitchCommands.sendPacket(sw, (short) pktIn.getInPort(), rstPkt);
                        return Command.STOP;
                    }
                }
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

    @Override public void switchRemoved(long switchId) {}
    @Override public void switchActivated(long switchId) {}
    @Override public void switchPortChanged(long switchId, ImmutablePort port, PortChangeType type) {}
    @Override public void switchChanged(long switchId) {}

    @Override
    public String getName() { return MODULE_NAME; }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return OFType.PACKET_IN == type &&
               (name.equals(ArpServer.MODULE_NAME) || name.equals(DeviceManagerImpl.MODULE_NAME));
    }

    @Override public boolean isCallbackOrderingPostreq(OFType type, String name) { return false; }

    @Override public Collection<Class<? extends IFloodlightService>> getModuleServices() { return null; }
    @Override public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() { return null; }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> deps = new ArrayList<>();
        deps.add(IFloodlightProviderService.class);
        deps.add(IDeviceService.class);
        return deps;
    }
}
