package edu.wisc.cs.sdn.sr;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.UDP;

import net.floodlightcontroller.packet.RIPv2Entry;
import java.util.Timer;
import java.util.Random;

/**
  * Implements RIP.  * @author Anubhavnidhi Abhashkumar and Aaron Gember-Jacobson */
public class RIP implements Runnable
{
    private static final int RIP_MULTICAST_IP = 0xE0000009;
    private static final byte[] BROADCAST_MAC = {(byte)0xFF, (byte)0xFF, 
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF};
    
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
        RIPv2 ripPacket = new RIPv2();

        ripPacket.setCommand((byte)1);

		for(Iface iface : this.router.getInterfaces().values())
        {
			UDP udpPacket = new UDP();
			IPv4 ipPacket = new IPv4();
			Ethernet etherPacket = new Ethernet();

			System.out.println("INITPKT");

			udpPacket.setSourcePort(UDP.RIP_PORT);
			udpPacket.setDestinationPort(UDP.RIP_PORT);
			udpPacket.setPayload(ripPacket);

			ipPacket.setProtocol(IPv4.PROTOCOL_UDP);
			ipPacket.setTtl((byte)64);
			ipPacket.setFlags((byte)2);
			// TODO: Somehow guarantee uniqueness
			ipPacket.setIdentification((short)(new Random()).nextInt(Short.MAX_VALUE+1));
			ipPacket.setDestinationAddress(RIP_MULTICAST_IP);
			ipPacket.setSourceAddress(iface.getIpAddress());        
			ipPacket.setPayload(udpPacket);
			ipPacket.serialize(); // trigger checksum calculation

			etherPacket.setEtherType(Ethernet.TYPE_IPv4);
			etherPacket.setSourceMACAddress(iface.getMacAddress().toString());
			etherPacket.setDestinationMACAddress(BROADCAST_MAC);
			etherPacket.setPayload(ipPacket);

			this.router.sendPacket(etherPacket, iface);
        }
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

			RIPv2 ripPacket = new RIPv2();

			ripPacket.setCommand((byte)2);

			for(RouteTableEntry rtEntry : this.router.getRouteTable().getEntries())
			{
				// metric is 0, change
				RIPv2Entry entry
				   = new RIPv2Entry(	rtEntry.getDestinationAddress(),
										rtEntry.getMaskAddress(),
										0 );

				ripPacket.addEntry(entry);      
			}

			for(Iface iface : this.router.getInterfaces().values())
			{
				UDP udpPacket = new UDP();
				IPv4 ipPacket = new IPv4();
				Ethernet etherPacket = new Ethernet();

				System.out.println("UPDATEPKT");

				udpPacket.setSourcePort(UDP.RIP_PORT);
				udpPacket.setDestinationPort(UDP.RIP_PORT);
				udpPacket.setPayload(ripPacket);

				ipPacket.setProtocol(IPv4.PROTOCOL_UDP);
				ipPacket.setTtl((byte)64);
				ipPacket.setFlags((byte)2);
				// TODO: Somehow guarantee uniqueness
				ipPacket.setIdentification((short)(new Random()).nextInt(Short.MAX_VALUE+1));
				ipPacket.setDestinationAddress(RIP_MULTICAST_IP);
				ipPacket.setSourceAddress(iface.getIpAddress());        
				ipPacket.setPayload(udpPacket);
				ipPacket.serialize(); // trigger checksum calculation

				etherPacket.setEtherType(Ethernet.TYPE_IPv4);
				etherPacket.setSourceMACAddress(iface.getMacAddress().toString());
				etherPacket.setDestinationMACAddress(BROADCAST_MAC);
				etherPacket.setPayload(ipPacket);

				this.router.sendPacket(etherPacket,iface);      
			}
        }
	}
}
