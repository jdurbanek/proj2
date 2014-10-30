package edu.wisc.cs.sdn.sr;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;

import java.util.Timer;
import java.util.Random;
import java.util.List;
import java.util.LinkedList;
import java.util.Iterator;
/**
  * Implements RIP.  * @author Anubhavnidhi Abhashkumar and Aaron Gember-Jacobson */
public class RIP implements Runnable
{
    public static final int RIP_MULTICAST_IP = 0xE0000009;
    private static final byte[] BROADCAST_MAC = {(byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF};
    
    public static final int MAX_HOP = 16;

    /** Send RIP updates every 10 seconds */
    private static final int UPDATE_INTERVAL = 10;

    /** Timeout routes that neighbors last advertised more than 30 seconds ago*/
    private static final int TIMEOUT = 30;

    /** Router whose route table is being managed */
	private Router router;

    /** Thread for periodic tasks */
    private Thread tasksThread;

	public RIP(Router router)
	{ 
        this.router = router; 
        this.tasksThread = new Thread(this);
    }

	public void init()
	{
        // If we are using static routing, then don't do anything
        if (this.router.getRouteTable().getEntries().size() > 0)
        { return; }

        System.out.println("RIP: Build initial routing table");
        for(Iface iface : this.router.getInterfaces().values())
        {
            this.router.getRouteTable().addEntry(
                    (iface.getIpAddress() & iface.getSubnetMask()),
                    0, // No gateway for subnets this router is connected to
                    iface.getSubnetMask(), iface.getName());
        }
        System.out.println("Route Table:\n"+this.router.getRouteTable());

		this.tasksThread.start();

        /*********************************************************************/
        /* TODO: Add other initialization code as necessary                  */

        /*********************************************************************/

		// Initial broadcast request
		this.sendRip((byte)1);
	}

    /**
      * Handle a RIP packet received by the router.
      * @param etherPacket the Ethernet packet that was received
      * @param inIface the interface on which the packet was received
      */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
        // Make sure it is in fact a RIP packet
        if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
        { return; } 
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        if (ipPacket.getProtocol() != IPv4.PROTOCOL_UDP)
        { return; } 
		UDP udpPacket = (UDP)ipPacket.getPayload();
        if (udpPacket.getDestinationPort() != UDP.RIP_PORT)
        { return; }
		RIPv2 ripPacket = (RIPv2)udpPacket.getPayload();

        /*********************************************************************/
        /* TODO: Handle RIP packet                                           */

        /*********************************************************************/
		System.out.println("RECVPKT");

		// Response received, update routing table
		if(ripPacket.getCommand() == ((byte)2))
		{
			boolean updated = false;

			for(RIPv2Entry entry : ripPacket.getEntries())
			{
				//check to see if it is already in the routetable if it
				//isn't add it, if is update
				RouteTable routeTable;
				RouteTableEntry rte;
				
				routeTable = this.router.getRouteTable();
				rte = routeTable.findEntry(	entry.getAddress(),
											entry.getSubnetMask() );

				if(rte == null)
				{
					routeTable.addEntry(	entry.getAddress(),
											entry.getNextHopAddress(),
											entry.getSubnetMask(),
											inIface.getName() );
					updated = true;
				}
				else
				{
					// Update routing table if received route has smaller number
					// of hops
				 	if(rte.getDestinationAddress() == entry.getAddress()
					&& rte.getDistance() > entry.getMetric())
					{
						routeTable.updateEntry(	entry.getAddress(),
												entry.getNextHopAddress(),
												entry.getSubnetMask(),
												inIface.getName() );

						updated = true;
					}
					else if(rte.getDestinationAddress() == entry.getAddress()
					&& rte.getDistance() == entry.getMetric())
					{
						rte.updateTimestamp();
					}
				}

				System.out.println(	"Routing table updated: \n"+
									routeTable.toString() );
			}
			
			if(updated)
			{
				this.sendRip((byte)2);
			}
		}
		// Request received, reply
		else if(ripPacket.getCommand() == ((byte)1))
		{
			this.sendRip(	(byte)2,
							inIface,
							ipPacket.getSourceAddress(),
							etherPacket.getSourceMAC().toString() );
		}
	}

	// Set inIface = null, dest = -1, and destMac = null to broadcast
    private void sendRip(byte command, Iface inIface, int dest, String destMac)
	{
		Iterator<Iface> ifaceIter
			= this.router.getInterfaces().values().iterator();

		boolean done = false;

		while(!done)
		{
			RIPv2 ripPacket = new RIPv2();
			Iface iface;

			// broadcast
			if(inIface == null)
			{
				if(ifaceIter.hasNext())
				{
					iface = ifaceIter.next();
				}
				else
				{
					// TODO: Avoid premature loop exit
					break;
				}
			}
			// not broadcast
			else
			{
				iface = inIface;
				
				done = true;
			}

			ripPacket.setCommand(command);

			// For simplicity in implementing split horizon, packet construction
			// is done once for each interface
			for(	RouteTableEntry rtEntry:
					this.router.getRouteTable().getEntries() )
			{
				// Split horizon: do not send route received from neighbor back to
				// it
				if(rtEntry.getDestinationAddress() != dest)
				{
					RIPv2Entry entry
					   = new RIPv2Entry(	rtEntry.getDestinationAddress(),
											rtEntry.getMaskAddress(),
											rtEntry.getDistance() + 1);

					ripPacket.addEntry(entry);      
				}
			}

			UDP udpPacket = new UDP();
			IPv4 ipPacket = new IPv4();
			Ethernet etherPacket = new Ethernet();

			System.out.println("SENDRIP");

			udpPacket.setSourcePort(UDP.RIP_PORT);
			udpPacket.setDestinationPort(UDP.RIP_PORT);
			udpPacket.setPayload(ripPacket);

			ipPacket.setProtocol(IPv4.PROTOCOL_UDP);
			ipPacket.setTtl((byte)64);
			ipPacket.setFlags((byte)2);
			// TODO: Somehow guarantee uniqueness
			ipPacket.setIdentification((short)(new Random()).nextInt(Short.MAX_VALUE+1));
			ipPacket.setDestinationAddress((dest == -1)?RIP_MULTICAST_IP:dest);
			ipPacket.setSourceAddress(iface.getIpAddress());        
			ipPacket.setPayload(udpPacket);
			ipPacket.serialize(); // trigger checksum calculation

			etherPacket.setEtherType(Ethernet.TYPE_IPv4);
			etherPacket.setSourceMACAddress(iface.getMacAddress().toString());

			if(destMac == null)
			{
				etherPacket.setDestinationMACAddress(BROADCAST_MAC);
			}
			else
			{
				etherPacket.setDestinationMACAddress(destMac);
			}

			etherPacket.setPayload(ipPacket);

			this.router.sendPacket(etherPacket,iface);      
		}
	}

    private void sendRip(byte command)
	{
		this.sendRip(command, null, -1, null);
	}

    /**
      * Perform periodic RIP tasks.
      */
	@Override
	public void run() 
    {
        /*********************************************************************/
        /* TODO: Send period updates and time out route table entries        */

        /*********************************************************************/
        while(true)
        {
			try
			{
				tasksThread.sleep(RIP.UPDATE_INTERVAL*1000);
			}
			catch(Exception e)
			{
				System.out.println(e.getMessage());
			}

			// Remove expired routing table entries
			List<RouteTableEntry> rteToRemove
				= new LinkedList<RouteTableEntry>();

			for(RouteTableEntry rte : this.router.getRouteTable().getEntries())
			{
				if((System.currentTimeMillis()/1000L
				- rte.getTimestamp() >= TIMEOUT))
				{
					rteToRemove.add(rte);
				}
			}
			
			for(RouteTableEntry rte : rteToRemove)
			{
				this.router.getRouteTable().removeEntry
					(rte.getDestinationAddress(), rte.getMaskAddress());
			}

			this.sendRip((byte)2);
        }
	}
}
