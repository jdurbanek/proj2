package edu.wisc.cs.sdn.sr;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Iterator;
import java.util.Map;

import edu.wisc.cs.sdn.sr.vns.VNSComm;
import edu.wisc.cs.sdn.sr.RouteTable;
import edu.wisc.cs.sdn.sr.RouteTableEntry;

import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.util.MACAddress;

/**
 * @author Aaron Gember-Jacobson
 */
public class Router 
{
	/** User under which the router is running */
	private String user;
	
	/** Hostname for the router */
	private String host;
	
	/** Template name for the router; null if no template */
	private String template;
	
	/** Topology ID for the router */
	private short topo;
	
	/** List of the router's interfaces; maps interface name's to interfaces */
	private Map<String,Iface> interfaces;
	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	/** PCAP dump file for logging all packets sent/received by the router;
	 *  null if packets should not be logged */
	private DumpFile logfile;
	
	/** Virtual Network Simulator communication manager for the router */
	private VNSComm vnsComm;

    /** RIP subsystem */
    private RIP rip;
	
	/**
	 * Creates a router for a specific topology, host, and user.
	 * @param topo topology ID for the router
	 * @param host hostname for the router
	 * @param user user under which the router is running
	 * @param template template name for the router; null if no template
	 */
	public Router(short topo, String host, String user, String template)
	{
		this.topo = topo;
		this.host = host;
		this.setUser(user);
		this.template = template;
		this.logfile = null;
		this.interfaces = new HashMap<String,Iface>();
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache(this);
		this.vnsComm = null;
        this.rip = new RIP(this);
	}
	
	public void init()
	{ this.rip.init(); }
	
	/**
	 * @param logfile PCAP dump file for logging all packets sent/received by 
	 * 		  the router; null if packets should not be logged
	 */
	public void setLogFile(DumpFile logfile)
	{ this.logfile = logfile; }
	
	/**
	 * @return PCAP dump file for logging all packets sent/received by the
	 *         router; null if packets should not be logged
	 */
	public DumpFile getLogFile()
	{ return this.logfile; }
	
	/**
	 * @param template template name for the router; null if no template
	 */
	public void setTemplate(String template)
	{ this.template = template; }
	
	/**
	 * @return template template name for the router; null if no template
	 */
	public String getTemplate()
	{ return this.template; }
		
	/**
	 * @param user user under which the router is running; if null, use current 
	 *        system user
	 */
	public void setUser(String user)
	{
		if (null == user)
		{ this.user = System.getProperty("user.name"); }
		else
		{ this.user = user; }
	}
	
	/**
	 * @return user under which the router is running
	 */
	public String getUser()
	{ return this.user; }
	
	/**
	 * @return hostname for the router
	 */
	public String getHost()
	{ return this.host; }
	
	/**
	 * @return topology ID for the router
	 */
	public short getTopo()
	{ return this.topo; }
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * @return list of the router's interfaces; maps interface name's to
	 * 	       interfaces
	 */
	public Map<String,Iface> getInterfaces()
	{ return this.interfaces; }
	
	/**
	 * @param vnsComm Virtual Network System communication manager for the router
	 */
	public void setVNSComm(VNSComm vnsComm)
	{ this.vnsComm = vnsComm; }
	
	/**
	 * Close the PCAP dump file for the router, if logging is enabled.
	 */
	public void destroy()
	{
		if (logfile != null)
		{ this.logfile.close(); }
	}
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loading routing table");
		System.out.println("---------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("---------------------------------------------");
	}
	
	/**
	 * Add an interface to the router.
	 * @param ifaceName the name of the interface
	 */
	public Iface addInterface(String ifaceName)
	{
		Iface iface = new Iface(ifaceName);
		this.interfaces.put(ifaceName, iface);
		return iface;
	}
	
	/**
	 * Gets an interface on the router by the interface's name.
	 * @param ifaceName name of the desired interface
	 * @return requested interface; null if no interface with the given name 
	 * 		   exists
	 */
	public Iface getInterface(String ifaceName)
	{ return this.interfaces.get(ifaceName); }
	
	/**
	 * Send an Ethernet packet out a specific interface.
	 * @param etherPacket an Ethernet packet with all fields, encapsulated
	 * 		  headers, and payloads completed
	 * @param iface interface on which to send the packet
	 * @return true if the packet was sent successfully, otherwise false
	 */
	public boolean sendPacket(Ethernet etherPacket, Iface iface)
	{ return this.vnsComm.sendPacket(etherPacket, iface.getName()); }

	public RouteTableEntry longestPrefixMatch(int destAddr)
	{
		List<RouteTableEntry> rteList;
		Iterator<RouteTableEntry> rteIter;
		RouteTableEntry rteMatch = null;
		int rteMatchLen = -1;

		rteList = this.getRouteTable().getEntries();
		rteIter = rteList.iterator();

		while(rteIter.hasNext())
		{
			RouteTableEntry rte;
			int suffixLen;
			int rtePrefix;
			int packetPrefix;

			rte = rteIter.next();
			suffixLen =	(int)
						(Math.log(~rte.getMaskAddress())
						/Math.log(2));

			rtePrefix =	rte.getDestinationAddress()
						&rte.getMaskAddress();

			packetPrefix = destAddr&rte.getMaskAddress();

			if(rtePrefix == packetPrefix
			&& 32-suffixLen < rteMatchLen)
			{
				rteMatchLen = 32-suffixLen;
				rteMatch = rte;
			}
		}

		return rteMatch;
	}

	public void sendIcmp(int destAddr, byte type, byte code)
	{
		RouteTableEntry rteMatch = this.longestPrefixMatch(destAddr);
		Ethernet etherPacket = new Ethernet();
		IPv4 ipPacket = new IPv4();
		ICMP icmpPacket = new ICMP();

		ArpEntry arp;
		Iface outIface;
		int next;

		if(rteMatch != null)
		{
			next = rteMatch.getDestinationAddress();
			arp = this.arpCache.lookup(next);
			outIface = this.getInterface(rteMatch.getInterface());

			// TODO: Generate checksum
			icmpPacket.setIcmpType(type);
			icmpPacket.setIcmpCode(code);

			// TODO: Correctly set TTL and options
			ipPacket.setSourceAddress(outIface.getIpAddress());
			ipPacket.setDestinationAddress(destAddr);
			ipPacket.setPayload(icmpPacket);

			etherPacket.setPayload(ipPacket);

			if(arp == null)
			{
				this.arpCache.waitForArp(etherPacket, outIface, next);

				System.out.println("Packet waits for ARP");
			}
			else
			{
				String srcMac = outIface.getMacAddress().toString();
				String destMac = arp.getMac().toString();

				etherPacket.setSourceMACAddress(srcMac);
				etherPacket.setDestinationMACAddress(destMac);

				this.sendPacket(etherPacket, outIface);
				System.out.println("Packet sent");
			}
		}
	}
	
	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received ipPacket: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		System.out.println("FOO");
		/********************************************************************/
		/* TODO: Handle ipPackets                                             */
		
		/********************************************************************/
		short etherType = etherPacket.getEtherType();

		if(etherType == Ethernet.TYPE_IPv4)
		{
			IPv4 ipPacket = (IPv4)etherPacket.getPayload();
			int dest = ipPacket.getDestinationAddress();

			System.out.println("IPv4");

			// TODO: fix checksum
			if(ipPacket.getChecksum() == ipPacket.computeChecksum() || true)
			{
				System.out.println("BAR "+inIface.getIpAddress());

				if(dest == inIface.getIpAddress())
				{
					if(ipPacket.getProtocol() == IPv4.PROTOCOL_ICMP)
					{
						System.out.println("ICMP");

						// Send the ICMP ipPacket back to the host
						String srcMac = inIface.getMacAddress().toString();
						String destMac = etherPacket.getSourceMAC().toString();
						int srcAddr = inIface.getIpAddress();
						int destAddr = ipPacket.getSourceAddress();

						etherPacket.setSourceMACAddress(srcMac);
						etherPacket.setDestinationMACAddress(destMac);
						ipPacket.setSourceAddress(srcAddr);
						ipPacket.setDestinationAddress(destAddr);
						this.sendPacket(etherPacket, inIface);
					}
					else if(ipPacket.getProtocol() == IPv4.PROTOCOL_UDP)
					{
						UDP udpPacket = (UDP)ipPacket.getPayload();

						if(udpPacket.getDestinationPort() == UDP.RIP_PORT)
						{
							// TODO: Handle RIP
						}
						else
						{
							// TODO: Send ICMP type 3 code 3
						}
					}
				}
				else
				{
					RouteTableEntry rteMatch;
					int next;
					Iface outIface;
					ArpEntry arp;

					rteMatch
						= this.longestPrefixMatch
							(ipPacket.getDestinationAddress());

					next = rteMatch.getDestinationAddress();
					outIface = this.getInterface(rteMatch.getInterface());
					arp = this.arpCache.lookup(next);

					if(arp == null)
					{
						this.arpCache.waitForArp(etherPacket, outIface, next);

						System.out.println("Packet waits for ARP");
					}
					else
					{
						String srcMac = outIface.getMacAddress().toString();
						String destMac = arp.getMac().toString();

						// TODO: Handle TTL = 0
						ipPacket.setTtl((byte)(ipPacket.getTtl()-1));

						etherPacket.setSourceMACAddress(srcMac);
						etherPacket.setDestinationMACAddress(destMac);
						this.sendPacket(etherPacket, outIface);

						System.out.println("Packet sent");
					}
				}
			}
			else
			{
				// TODO: handle errors
				System.out.println("Checksum mismatch");
				System.out.println("OLD: "+ipPacket.getChecksum());
				System.out.println("NEW: "+ipPacket.computeChecksum());
			}
		}
		else if(etherType == Ethernet.TYPE_ARP)
		{
				System.out.println("ARP");
				this.handleArpPacket(etherPacket, inIface);
		}
	}
	
	/**
	 * Handle an ARP packet received on a specific interface.
	 * @param etherPacket the complete ARP packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	private void handleArpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an ARP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_ARP)
		{ return; }
		
		// Get ARP header
		ARP arpPacket = (ARP)etherPacket.getPayload();
		int targetIp = ByteBuffer.wrap(
				arpPacket.getTargetProtocolAddress()).getInt();
		
		switch(arpPacket.getOpCode())
		{
		case ARP.OP_REQUEST:
			// Check if request is for one of my interfaces
			if (targetIp == inIface.getIpAddress())
			{ this.arpCache.sendArpReply(etherPacket, inIface); }
			break;
		case ARP.OP_REPLY:
			// Check if reply is for one of my interfaces
			if (targetIp != inIface.getIpAddress())
			{ break; }
			
			// Update ARP cache with contents of ARP reply
		    int senderIp = ByteBuffer.wrap(
				    arpPacket.getSenderProtocolAddress()).getInt();
			ArpRequest request = this.arpCache.insert(
					new MACAddress(arpPacket.getSenderHardwareAddress()),
					senderIp);
			
			// Process pending ARP request entry, if there is one
			if (request != null)
			{				
				for (Ethernet packet : request.getWaitingPackets())
				{
					/*********************************************************/
					/* TODO: send packet waiting on this request             */
					
					/*********************************************************/
					System.out.println("PQUEUE");

					// TODO: get correct inIface
					this.handlePacket(packet, inIface);
				}
			}
			break;
		}
	}
}
