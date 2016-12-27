package TM3;

import java.util.LinkedList;
import java.util.concurrent.ConcurrentHashMap;

public class Constants {

	public static final int HEADERLENGTH = 8;
	public static final int LISTENPORT = 6000;
	public static final long SynSequenceNumber =0;
	public static final long FinMessageLength =65534;
	public static int numberOfPipes=1;
	public static final int UplinkStartSeqNumber =1;
	public static final int DownlinkStartSeqNumber =0;
	public static volatile  LinkedList<Pipe> pipeList = new LinkedList<Pipe>();
	public static volatile ConcurrentHashMap<Integer,RemoteSocketConnection> connectionMap = new ConcurrentHashMap<Integer,RemoteSocketConnection>();
	public static final String connectionReset ="Connection reset";
	public static final int maxMessageLength = 4096;

}
