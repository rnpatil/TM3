#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/timeb.h>
#include <fcntl.h>
#include <stdarg.h>
#include <time.h>

typedef unsigned char BYTE;
typedef unsigned int DWORD;
typedef unsigned short WORD;

void Error(const char * format, ...) {
	char msg[4096];
	va_list argptr;
	va_start(argptr, format);
	vsprintf(msg, format, argptr);
	va_end(argptr);
	fprintf(stderr, "Error: %s\n", msg);
	exit(-1);
}

void Log(const char * format, ...) {
	char msg[2048];
	va_list argptr;
	va_start(argptr, format);
	vsprintf(msg, format, argptr);
	va_end(argptr);
	fprintf(stderr, "%s\n", msg);
}

void CheckData(BYTE * buf, int size) {
	for (int i=0; i<size; i++) if (buf[i] != 'A' + i % 26) {
		Error("Received wrong data.");
	}
}

int Send_Blocking(int sockFD, const BYTE * data, int len) {
	int nSent = 0;
	while (nSent < len) {
		int n = send(sockFD, data + nSent, len - nSent, 0);
		if (n >= 0) {
			nSent += n;
		} else if (n < 0 && (errno == ECONNRESET || errno == EPIPE)) {
			Log("Connection closed.");
			close(sockFD);
			return -1;
		} else {
			Error("Unexpected error %d: %s.", errno, strerror(errno));
		}
	}
	return 0;
}

int Recv_Blocking(int sockFD, BYTE * data, int len) {
	int nRecv = 0;
	while (nRecv < len) {
		int n = recv(sockFD, data + nRecv, len - nRecv, 0);
		if (n > 0) {
			nRecv += n;
		} else if (n == 0 || (n < 0 && errno == ECONNRESET)) {
			Log("Connection closed.");
			close(sockFD);
			return -1;
		} else {
			Error("Unexpected error %d: %s.", errno, strerror(errno));
		}
	}
	return 0;
}


int GetRandom(int min, int max) {
	DWORD r = 0;
	for (int i=0; i<4; i++) {
		r = (r | (DWORD)(rand() % 256)) << 8;
	}
	
	return int(r % (max-min+1) + min);
}

void DoClient(const char * svrIP, int svrPort, int nReq, int minSize, int maxSize) {
	BYTE * buf = (BYTE *)malloc(maxSize);	
	
	struct sockaddr_in serverAddr;
	memset(&serverAddr, 0, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons((unsigned short) svrPort);
	inet_pton(AF_INET, svrIP, &serverAddr.sin_addr);
	
	for (int i=0; i<nReq; i++) {		//Make nReq requests
		//Create the socket
		int sockFD = socket(AF_INET, SOCK_STREAM, 0);
		if (sockFD == -1) {
			Error("Cannot create socket.");		
		}

		int size = GetRandom(minSize, maxSize);	//Randomize the request size
				
		struct timeb t;		
		ftime(&t);	
		double beginTime =  t.time + t.millitm / (double) 1000.0f;	//record when we start
		
		//Connect to server
		if (connect(sockFD, (const struct sockaddr *) &serverAddr, sizeof(serverAddr)) != 0) {
			Error("Cannot connect to server %s:%d.", svrIP, svrPort);
		}
						
		//Send 4-byte request
		if (Send_Blocking(sockFD, (const BYTE *)&size, 4) < 0) break;
		
		//Read response
		if (Recv_Blocking(sockFD, buf, size) < 0) break;
		
		ftime(&t);
		double endTime =  t.time + t.millitm / (double) 1000.0f;	//record when we stop
		
		Log("Transaction %d: %d bytes, %.2lf seconds.", i, size, endTime - beginTime);
		
		CheckData(buf, size);
		close(sockFD);
	}
	
	free(buf);
}

int main(int argc, char * * argv) {
	
	if (argc != 6) {
		Log("Usage: %s [server IP] [server Port] [# requests] [min_request_size] [max_request_size]", argv[0]);
		return -1;
	}
	
	const char * serverIP = argv[1];
	int port = atoi(argv[2]);
	int nReq = atoi(argv[3]);
	int minSize = atoi(argv[4]);
	int maxSize = atoi(argv[5]);
	
	srand(time(NULL));
	
	DoClient(serverIP, port, nReq, minSize, maxSize);
	return 0;
}

