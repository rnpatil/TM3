package TM3;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.SocketException;
public class remote_proxy {

	private static ServerSocket serversocket;

	public static void main(String args[]) throws IOException {
		try {
			serversocket = new ServerSocket(Constants.LISTENPORT);

			System.out.println("TM3 remote proxy");
			System.out.println("version 1.0");
			System.out.println("TCP Build");

			int pipeNumber=Integer.parseInt(args[0]);
			Constants.numberOfPipes=pipeNumber;
			int startPipeNumber=0;
			
			while (true) {
				Pipe p = new Pipe(serversocket.accept(),++startPipeNumber);

				Constants.pipeList.add(p);
				p.start();
			}
		}

		catch(SocketException se)
		{
			serversocket.close();
		}
		finally {
			serversocket.close();
		}

	}



}