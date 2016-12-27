package TM3;
import java.util.Arrays;

public class PacketHeader {

	private  int connID=0;
	private  long SeqNo=-1;
	private  int length=0;
	public int getConnID() {
		return connID;
	}

	public long getSeqNo() {
		return SeqNo;
	}

	public int getLength() {
		return length;
	}




	PacketHeader(final byte[] headerData)
	{
		this.connID = (int )littleEndian(Arrays.copyOfRange(headerData, 0, 2)); 
		this.SeqNo=littleEndian(Arrays.copyOfRange(headerData, 2, 6));
		this.length=(int) littleEndian(Arrays.copyOfRange(headerData,6,8));
	}

	public static long littleEndian(byte[] bytes) {
		long ret = 0;
		for (int i = bytes.length - 1; i >= 0; i--) {
			ret <<= 8;
			ret |= (int) bytes[i] & 0xFF;
		}

		return ret;
	}




}