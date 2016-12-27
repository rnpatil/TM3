package TM3;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;

public class Pipe extends Thread{

	private RemoteSocketConnection remoteConnection=null;
	private  Socket pipeSocket = null;
	private SocketAddress remoteSocketAddress =null;

	public Socket getPipeSocket() {
		return pipeSocket;
	}

	public void setPipeSocket(Socket pipeSocket) {
		this.pipeSocket = pipeSocket;
	}


	private static byte[]destinationIP=new byte[4];
	private  int pipeNumber;
	private static int packetLength=0;
	private byte reason;
	private static byte[]destinationPort=new byte[2];
	private static String destIp;
	private static int destPort;
	private static InetAddress destIPAddr=null;



	public Pipe(java.net.Socket pipeSocket,int pipeNumber)
	{
		this.pipeSocket = pipeSocket;
		this.pipeNumber=pipeNumber;
		System.out.println("Starting pipe: "+pipeNumber);
		System.out.println("Pipe " + pipeNumber + " established, Local Port = " + pipeSocket.getPort()+", TCP = default, Interface = default");
	}

	public void run() {

		try {
			BufferedInputStream in = new BufferedInputStream(pipeSocket.getInputStream());
			int pc=0;

			while (true) {
				pc = 0;
				byte[] packetHeaderData = new byte[Constants.HEADERLENGTH];

				while (pc < Constants.HEADERLENGTH) {
					{
						packetHeaderData[pc] = (byte) in.read();
						pc++;
					}
				}

				pc=0;
				PacketHeader packetHeader = new PacketHeader(packetHeaderData);

				if (packetHeader.getSeqNo() == -1) {
					break;
				}

				if(packetHeader.getSeqNo()==Constants.SynSequenceNumber)
				{
					int i=0;
					for(i=0;i<4;i++)
					{
						destinationIP[i]=(byte)in.read();
					}
					i=0;

					destIp = ((int) destinationIP[0] & 0xFF) + "." + ((int) destinationIP[1] & 0xFF) + "." + ((int) destinationIP[2] & 0xFF) + "."
							+ ((int) destinationIP[3] & 0xFF);

					destIPAddr = InetAddress.getByName(destIp);

					for(i =0;i<2;i++)
					{
						destinationPort[i]=(byte)in.read();
					}

					destPort=getPort(destinationPort);

					remoteSocketAddress = new InetSocketAddress(destIPAddr, destPort);
					java.net.Socket remoteSocket = new java.net.Socket();

					/**
					 * 
					 * Connect to remote server
					 */
					remoteSocket.connect(remoteSocketAddress);

					if(!Constants.connectionMap.containsKey(packetHeader.getConnID()))
					{
						remoteConnection = new RemoteSocketConnection(remoteSocket);
						remoteConnection.setExpectedSequenceNumber(Constants.UplinkStartSeqNumber);
						remoteConnection.setDownlinkSequenceNumber(Constants.DownlinkStartSeqNumber);
						remoteConnection.setTcpConnectionID(packetHeader.getConnID());
						Constants.connectionMap.put(packetHeader.getConnID(), remoteConnection);
					}
					else
					{
						remoteConnection = Constants.connectionMap.get(packetHeader.getConnID());
						remoteConnection.setRemoteEndpointSocket(remoteSocket);
						remoteConnection.setExpectedSequenceNumber(Constants.UplinkStartSeqNumber);
						remoteConnection.setDownlinkSequenceNumber(Constants.DownlinkStartSeqNumber);
						remoteConnection.setTcpConnectionID(packetHeader.getConnID());
						Constants.connectionMap.put(packetHeader.getConnID(), remoteConnection);
					}

					RemoteProxyUplink remoteProxyUplink = new RemoteProxyUplink(remoteConnection);

					RemoteProxyDownlink remoteProxyDownlink=new RemoteProxyDownlink(remoteConnection);

										System.out.println(
												"New outgoing connection : {" + remoteConnection.getRemoteEndpointSocket().getLocalSocketAddress().toString()
												+ " - " + remoteConnection.getRemoteEndpointSocket().getRemoteSocketAddress().toString() + " cID="+packetHeader.getConnID()+ "}");

					remoteProxyUplink.start();
					remoteProxyDownlink.start();

				}
				else if(packetHeader.getLength()==Constants.FinMessageLength)
				{

					if(!Constants.connectionMap.containsKey(packetHeader.getConnID()))
					{
						remoteConnection = new RemoteSocketConnection();
						Constants.connectionMap.put(packetHeader.getConnID(), remoteConnection);
					}

					remoteConnection = Constants.connectionMap.get(packetHeader.getConnID());

					byte[] data = new byte[1];

					reason=(byte) in.read();
					System.out.println("Fin Message :: Reason : "+reason);

					data[0] =reason;

					// fin or rst

					/**
					 * You can ignore the reason"
					 */

					remoteConnection.addUplinkData(packetHeader.getSeqNo(), data);
					remoteConnection.setFin(true);
					Constants.connectionMap.put(packetHeader.getConnID(),remoteConnection);

				}


				/**
				 *  LP Data Message
				 * 
				 * 
				 */
				else
				{
					if(!Constants.connectionMap.containsKey(packetHeader.getConnID()))
					{
						remoteConnection = new RemoteSocketConnection();
						Constants.connectionMap.put(packetHeader.getConnID(), remoteConnection);
					}

					remoteConnection = Constants.connectionMap.get(packetHeader.getConnID());
					packetLength=packetHeader.getLength();

					// payload length  = total length - 8(bytes of header )

					byte[] data = new byte[packetLength-Constants.HEADERLENGTH];

					int i = 0;
					while (i < data.length) {
						data[i] = (byte) in.read();
						i++;
					}

					remoteConnection.addUplinkData(packetHeader.getSeqNo(), data);
					Constants.connectionMap.put(packetHeader.getConnID(),remoteConnection);
				}

			}

			/**
			 * Close pipe input stream
			 */
			in.close();

			System.out.println("ctrl c+here");

		} catch (IOException e) {
			e.printStackTrace();
		} 

		finally {	

		}

	}


	public static int getPort(byte[] portNumberBytes) {
		int portNumber = 0;
		for (int i = portNumberBytes.length - 1; i >= 0; i--) {
			portNumber <<= 8;
			portNumber |= (int) portNumberBytes[i] & 0xFF;
		}
		return portNumber;
	}
}
