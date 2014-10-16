package edu.wisc.cs.sdn.sr;

import net.floodlightcontroller.util.MACAddress;

/**
 * An interface on a router.
 * @author Aaron Gember-Jacobson
 */
public class Iface 
{
	private String name;
	private MACAddress macAddress;
	private int ipAddress;
	
	public Iface(String name)
	{
		this.name = name;
		this.macAddress = null;
		this.ipAddress = 0;
	}
	
	public String getName()
	{ return this.name; }
	
	public void setMacAddress(MACAddress mac)
	{ this.macAddress = mac; }
	
	public MACAddress getMacAddress()
	{ return this.macAddress; }

	public void setIpAddress(int ip)
	{ this.ipAddress = ip; }
	
	public int getIpAddress()
	{ return this.ipAddress; }
	
	public String toString()
	{
		return String.format("%s\tHWaddr %s\n\tinet addr %s",
				this.name, this.macAddress.toString(), 
				Util.intToDottedDecimal(this.ipAddress));
	}
}
