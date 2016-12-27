package TM3;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


public class RemoteProxyDownlink extends Thread {

	private final RemoteSocketConnection remoteConnection;

	RemoteProxyDownlink(RemoteSocketConnection remoteConnection) {
		this.remoteConnection = remoteConnection;
	}

	public void run() {

		boolean closedHard = false;
		byte[] reason = new byte[1];

		try {

			while (!remoteConnection.getRemoteEndpointSocket().isClosed()) {

				ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
				int recieveBufferSize = remoteConnection.getRemoteEndpointSocket().getReceiveBufferSize();
				if (recieveBufferSize > 0) {
					int reader = 0;
					byte[] data = new byte[recieveBufferSize];
					try {

						/*
						 * 
						 * reader will have -1 if connection has been closed 
						 */

						reader = remoteConnection.getRemoteEndpointSocket().getInputStream().read(data);
					} catch (Exception e) {
						if(e.getMessage().equalsIgnoreCase(Constants.connectionReset)){
							reason[0] = (byte) 0x99;
						}else{
							reason[0] = (byte) 0x88;
						}
						if(!Constants.connectionMap.containsKey(remoteConnection.getTcpConnectionID()))
						{
							closedHard = true;
						}
						break;
					}
					if (reader == -1) {
						closedHard = false;
						break;
					}
					outputStream.write(data, 0, reader);
				}

				List<byte[]> demuxedData = new ArrayList<byte[]>();

				if (outputStream.toByteArray().length <= Constants.maxMessageLength) {
					demuxedData.add(outputStream.toByteArray());
				}
				else if (outputStream.toByteArray().length > Constants.maxMessageLength) {
					demuxedData = divideDataChunks(outputStream.toByteArray(), Constants.maxMessageLength);
				} 

				int pipeNo = -1;
				byte[] connectionID =intToByteArray(remoteConnection.getTcpConnectionID());
				for (byte[] chunk : demuxedData) {
					pipeNo++;
					if(pipeNo >= Constants.numberOfPipes){
						pipeNo = 0;
					}

					byte[] sequenceNumber =longToByteArray(remoteConnection.getDownlinkSequenceNumber());
					remoteConnection.setDownlinkSequenceNumber(remoteConnection.getDownlinkSequenceNumber()+1);
					byte[] pipeMessageLength =intToByteArray(chunk.length+8);

					byte[] messageToLP = createPipeMessage(connectionID, sequenceNumber, pipeMessageLength, chunk);

					System.out.println(
							"Message written on pipe by RP  : {" + remoteConnection.getRemoteEndpointSocket().getLocalSocketAddress().toString()
							+ " - " + remoteConnection.getRemoteEndpointSocket().getRemoteSocketAddress().toString() + "}");


					Constants.pipeList.get(pipeNo).getPipeSocket().getOutputStream().write(messageToLP);
					Constants.pipeList.get(pipeNo).getPipeSocket().getOutputStream().flush();
				}

			}

			if(closedHard)
			{
				byte[] connectionID =intToByteArray(remoteConnection.getTcpConnectionID());
				byte[] sequenceNumber =longToByteArray(remoteConnection.getDownlinkSequenceNumber());
				remoteConnection.setDownlinkSequenceNumber(remoteConnection.getDownlinkSequenceNumber()+1);

				byte[] pipeMessageLength =intToByteArray(9);
				byte[] messageToLP = createPipeMessage(connectionID, sequenceNumber, pipeMessageLength, reason);
				Constants.pipeList.get(0).getPipeSocket().getOutputStream().write(messageToLP);
				Constants.pipeList.get(0).getPipeSocket().getOutputStream().flush();
				remoteConnection.getRemoteEndpointSocket().close();
			}

		} catch (Exception e) {
			// TODO Auto-generated catch block
			
		}
		finally {		
			System.out.println("TCP Connection Closed : " + remoteConnection.getTcpConnectionID());
			if (!remoteConnection.getRemoteEndpointSocket().isClosed()) {
				try {
					remoteConnection.getRemoteEndpointSocket().close();
					Constants.connectionMap.remove(remoteConnection.getTcpConnectionID());
				} catch (IOException e) {
					
				}
			}

		}

	}

	public static List<byte[]> divideDataChunks(byte[] source, int chunksize) {

		List<byte[]> result = new ArrayList<byte[]>();
		int start = 0;
		while (start < source.length) {
			int end = Math.min(source.length, start + chunksize);
			result.add(Arrays.copyOfRange(source, start, end));
			start += chunksize;
		}

		return result;
	}


	/**
	 * 
	 *  Append header and payload for pipe message
	 * @param connectionID
	 * @param sequenceNumber
	 * @param pipeMessageLength
	 * @param data
	 * @return
	 * @throws IOException
	 */
	public static byte[] createPipeMessage(byte[] connectionID,byte [] sequenceNumber,byte [] pipeMessageLength,byte [] data) throws IOException
	{
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(connectionID);
		out.write(sequenceNumber);
		out.write(pipeMessageLength);
		out.write(data);
		byte[] pipeMessage = out.toByteArray();

		return pipeMessage;
	}


	/**
	 * 
	 * @param number
	 * @return
	 */
	public static byte[] longToByteArray(long number)
	{
		byte[] ret = new byte[4];
		ret[0] = (byte) (number & 0xFF);   
		ret[1] = (byte) ((number >> 8) & 0xFF);   
		ret[2] = (byte) ((number >> 16) & 0xFF);   
		ret[3] = (byte) ((number >> 24) & 0xFF);
		return ret;
	}



	/***
	 * 
	 * @param number
	 * @return
	 */


	public static byte[] intToByteArray(int number)
	{
		byte[] ret = new byte[2];
		ret[0] = (byte) (number & 0xFF);   
		ret[1] = (byte) ((number >> 8) & 0xFF);   

		return ret;
	}


}
