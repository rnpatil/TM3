package TM3;

import java.util.TreeMap;

public class RemoteSocketConnection {

	private java.net.Socket remoteEndpointSocket;
	private TreeMap<Long, byte[]> uplinkData = new TreeMap<Long, byte[]>();
	private long expectedSequenceNumber;
	private long downlinkSequenceNumber;
	private int tcpConnectionID;
	private boolean isFin=false;
	public boolean isFin() {
		return isFin;
	}

	public void setFin(boolean isFin) {
		this.isFin = isFin;
	}

	public int getTcpConnectionID() {
		return tcpConnectionID;
	}

	public void setTcpConnectionID(int tcpConnectionID) {
		this.tcpConnectionID = tcpConnectionID;
	}

	public RemoteSocketConnection(java.net.Socket remoteEndpointSocket) {
		this.remoteEndpointSocket = remoteEndpointSocket;


	}

	public RemoteSocketConnection() {
	}

	public long getDownlinkSequenceNumber() {
		return downlinkSequenceNumber;
	}


	public void setDownlinkSequenceNumber(long downlinkSequenceNumber) {
		this.downlinkSequenceNumber = downlinkSequenceNumber;
	}

	public long getExpectedSequenceNumber() {
		return expectedSequenceNumber;
	}

	public void setExpectedSequenceNumber(long expectedSequenceNumber) {
		this.expectedSequenceNumber = expectedSequenceNumber;
	}

	public TreeMap<Long, byte[]> getUplinkData() {
		return uplinkData;
	}

	public void setUplinkData(TreeMap<Long, byte[]> uplinkData) {
		this.uplinkData = uplinkData;
	}

	public java.net.Socket getRemoteEndpointSocket() {
		return remoteEndpointSocket;
	}

	public void setRemoteEndpointSocket(java.net.Socket remoteEndpointSocket) {
		this.remoteEndpointSocket = remoteEndpointSocket;
	}

	public void addUplinkData(long seqNo, byte[] data) {
		this.uplinkData.put(seqNo, data);
	}

}
