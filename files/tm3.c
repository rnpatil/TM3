#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/route.h>

//#define DEBUG_DUMP

#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

MODULE_AUTHOR("Feng Qian");
MODULE_LICENSE("TODO");

static struct nf_hook_ops netfilter_ops_in; 
static struct nf_hook_ops netfilter_ops_out;

#define HOOK_UPLINK NF_INET_LOCAL_OUT
#define HOOK_DOWNLINK NF_INET_LOCAL_IN

typedef unsigned char BYTE;
typedef unsigned int DWORD;
typedef unsigned short WORD;

#ifdef USE_TEST_SERVER
	static char * testServerIP = "204.178.8.28";
	DWORD tIP;
	module_param(testServerIP, charp, 0000);
	MODULE_PARM_DESC(testServerIP, "Test Server IP");
#endif

DWORD rIP;
static char * remoteProxyIP = "0.0.0.0";
module_param(remoteProxyIP, charp, 0000);
MODULE_PARM_DESC(remoteProxyIP, "Remote Proxy IP Address");

static char * fwdInterface = "eth0";
module_param(fwdInterface, charp, 0000);
MODULE_PARM_DESC(fwdInterface, "Interface name");

static char * portList = "6001";
module_param(portList, charp, 0000);
MODULE_PARM_DESC(portList, "Port list");


#define LOCAL_PROXY_IP "127.0.0.1"
#define LOCAL_PROXY_PORT 1202

DWORD localHost;
WORD localProxyPort;

#define PROT_TCP 6
#define PROT_UDP 17

#define TCPFLAG_FIN 0x1
#define TCPFLAG_SYN 0x2
#define TCPFLAG_RST 0x4
#define TCPFLAG_ACK 0x10

#define MAGIC_MSS_VALUE 1459

typedef struct _IPv4_INFO {
	DWORD srcIP;
	DWORD dstIP;
	WORD protocol;
	WORD srcPort;
	WORD dstPort;
	int payloadLen;
	int ipHeaderLen;
	int tcpHeaderLen;
	BYTE tcpFlags;	
} IPv4_INFO;

static int pktCount = 0;

static WORD srcPort2serverPort[65536];
static DWORD srcPort2serverIP[65536];
//static BYTE srcPort2NoModify[65536];

static WORD forwardedPorts[65536];

void ReportError(const char * format, ...) {
	char dest[784];
	va_list argptr;
	va_start(argptr, format);
	vsprintf(dest, format, argptr);
	va_end(argptr);
	printk("+++++ERROR+++++: %s\n", dest);
}

void Log(const char * format, ...) {
	char dest[784];
	va_list argptr;
	va_start(argptr, format);
	vsprintf(dest, format, argptr);
	va_end(argptr);
	printk(KERN_INFO "[FENG] %s", dest);
}

static inline DWORD ReverseDWORD(DWORD x) {
	return
		(x & 0xFF) << 24 |
		(x & 0xFF00) << 8 |
		(x & 0xFF0000) >> 8 |
		(x & 0xFF000000) >> 24;
}

static inline WORD ReverseWORD(WORD x) {
	return
		(x & 0xFF) << 8 |
		(x & 0xFF00) >> 8;
}

static inline int ReverseINT(int x) {
	return (int)ReverseDWORD((DWORD)x);
}

const char * ConvertDWORDToIP(DWORD ip) {
	static char ipstr[5][128];
	static int count = 0;
	
	int i = count++;
	if (count == 5) count = 0;
	sprintf(ipstr[i], "%d.%d.%d.%d",
		(ip & 0x000000FF),
		(ip & 0x0000FF00) >> 8,
		(ip & 0x00FF0000) >> 16,
		(ip & 0xFF000000) >> 24
	);
	return ipstr[i];
}

DWORD ConvertIPToDWORD(const char * _ip) {
	char ip[128];
	DWORD ipc[4];
	
	strcpy(ip, _ip);
	int len = strlen(ip);	
	ip[len++] = '.';
	
	int i, j=0, k=0;
	for (i=0; i<len; i++) {
		if (ip[i] == '.') {
			ip[i] = 0;
			kstrtou32(ip + j, 10, &ipc[k++]);
			j = i+1;
			if (k == 4) break;
		}
	}

	return (ipc[0]) | (ipc[1] << 8) | (ipc[2] << 16)  | (ipc[3] << 24);
}

void ParsePortList(void) {
	char pl[256];
	
	strcpy(pl, portList);
	int len = strlen(pl);	
	pl[len++] = ',';
	
	int i, j=0;
	DWORD p;
	for (i=0; i<len; i++) {
		if (pl[i] == ',') {
			pl[i] = 0;
			kstrtou32(pl + j, 10, &p);
			forwardedPorts[p] = 1;
			Log("Forward port = %u\n", p);
			j = i+1;
		}
	}
}

void DumpPayload(const struct sk_buff * skb) {
}

int IsIPv4(const struct sk_buff * skb, IPv4_INFO * pInfo) {
		const BYTE * pkt_data = skb->data;
		
		if (pkt_data == NULL) {
			ReportError("skb data empty");
			return 0;
		}

		BYTE ipFlag = *pkt_data;
		if ((ipFlag & 0xF0) != 0x40) return 0; 
		
		if ((ipFlag & 0x0F) < 5) {
			ReportError("IPv4 flag: %d", (int)ipFlag);
			DumpPayload(skb);	
			return 0;	
		}
		
		DWORD ipOptionLength = 4 * ((ipFlag & 0x0F) - 5);
		WORD ipLength = ReverseWORD(*((WORD *)(pkt_data + 2)));
		
		if (ipLength != skb->len) {
			ReportError("skb len (%d) != ipLen (%d)", (int)skb->len, (int)ipLength);
			DumpPayload(skb);	
			return 0;
		}
		
		pInfo->srcIP = *((DWORD *)(pkt_data + 12));
		pInfo->dstIP = *((DWORD *)(pkt_data + 16));
		pInfo->protocol = *((BYTE *)(pkt_data + 9));
		
		pInfo->ipHeaderLen = 20 + ipOptionLength;
		
		pkt_data += ipOptionLength;	//***** Change offset
		if (pInfo->protocol == PROT_TCP) {
			if (ipLength < 20 + ipOptionLength + 20) {
				ReportError("Malformed TCP header");
				DumpPayload(skb);
				return 0;
			}						
			pInfo->srcPort = ReverseWORD(*((WORD *)(pkt_data + 20 + 0)));	
			pInfo->dstPort = ReverseWORD(*((WORD *)(pkt_data + 20 + 2)));	
			int tcpHeaderLen = (*((BYTE *)(pkt_data + 20 + 12)) & 0xF0) >> 2;
			
			pInfo->payloadLen = (int)ipLength - 20 - ipOptionLength - tcpHeaderLen;
			pInfo->tcpHeaderLen = tcpHeaderLen;
			pInfo->tcpFlags = *(pkt_data + 20 + 13);
			
			if (pInfo->payloadLen < 0) {
				ReportError("Malformed TCP packet");
				DumpPayload(skb);
				return 0;
			}
			
		} else if (pInfo->protocol == PROT_UDP) {			
			if (ipLength < 20 + ipOptionLength + 8) {
				ReportError("Malformed UDP header");
				DumpPayload(skb);
				return 0;
			}
			pInfo->srcPort = ReverseWORD(*((WORD *)(pkt_data + 20 + 0))); 
			pInfo->dstPort = ReverseWORD(*((WORD *)(pkt_data + 20 + 2))); 
			pInfo->tcpHeaderLen = 0;
			pInfo->tcpFlags = 0;
			
			pInfo->payloadLen = (int)ipLength - 20 - ipOptionLength - 8;
			if (pInfo->payloadLen < 0) {
				ReportError("Malformed UDP packet");
				DumpPayload(skb);
				return 0;
			}
			
		} else {
			pInfo->srcPort = 0;
			pInfo->dstPort = 0;
			pInfo->payloadLen = (int)ipLength - 20 - ipOptionLength;
			pInfo->tcpHeaderLen = 0;
		}
		
		return 1;
}


void AddIPOptionForSYN(struct sk_buff * skb, IPv4_INFO * pInfo) {
	//Use IP option (record route) to carry custom data
	
	static const int ipOptLen = 12;	//must be a multiple of 4
	
	if (skb->end - skb->tail < ipOptLen) {
		ReportError("Not enough space in SKB");
		return;
	}
	
	//TODO: a case where there is already IP options
	skb_put(skb, ipOptLen);
	
	BYTE * p = skb->data + pInfo->ipHeaderLen;
	memmove(p+ipOptLen, p, pInfo->tcpHeaderLen + pInfo->payloadLen);	
	*p = 7; *(p+1) = 11; *(p+2) = 12;
	*((DWORD *)(p+3)) = pInfo->dstIP;
	*((DWORD *)(p+8)) = 0;
	*((WORD *)(p+7)) = ReverseWORD(pInfo->dstPort);
			
	//Update IP len
	pInfo->ipHeaderLen += ipOptLen;
	WORD newIpLen = ReverseWORD((WORD)(pInfo->ipHeaderLen + pInfo->tcpHeaderLen + pInfo->payloadLen));
	*((WORD *)(skb->data + 2)) = newIpLen; //ip len

	*skb->data = 0x40 | (BYTE)(5 + (ipOptLen >> 2));
}

WORD IPChecksum(WORD *data, int len) {
	DWORD sum = 0;
	int i, j;
	for (i=0, j=0; i<len; i+=2, j++) {
		if (i == 10) continue;
		sum += data[j];		
	}
	
	while(sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);	
	
	return (WORD)(~sum);
}

WORD TCPChecksum(WORD * data, int len, DWORD srcIP, DWORD dstIP) {
	DWORD sum = 0; 
	int i, j;
	for (i=0, j=0; i<len; i+=2, j++) {
		if (i == 16) continue;
		if (i == len - 1) 
			sum += *((BYTE *)(data) + len - 1);
		else
			sum += data[j];
	}
	
	sum += (WORD)((srcIP & 0xFFFF0000) >> 16);	sum += (WORD)(srcIP & 0xFFFF);
	sum += (WORD)((dstIP & 0xFFFF0000) >> 16);	sum += (WORD)(dstIP & 0xFFFF);
	sum += ReverseWORD(0x0006);	
	sum += ReverseWORD((WORD)len);
					
	while(sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);	
			
	return (WORD)(~sum);	
}

void UpdateTCPIPChecksum(int dir, const struct sk_buff * skb, const IPv4_INFO * pInfo/*, DWORD srcIP, DWORD dstIP*/) {
	WORD ipSum /*, tcpSum*/;

	if (dir == HOOK_UPLINK) {
		*(WORD *)(skb->data + 10) = ipSum = IPChecksum((WORD *)skb->data, pInfo->ipHeaderLen);
		
		/*
		*(WORD *)(skb->data + pInfo->ipHeaderLen + 16) = 
				TCPChecksum((WORD *)(skb->data + pInfo->ipHeaderLen), pInfo->payloadLen + pInfo->tcpHeaderLen, srcIP, dstIP);
		*/
	}
	//Log("\t IP Checksum = %x TCP Checksum = %x\n", ipSum, tcpSum);
}

int ModifyPacket(unsigned int hooknum, struct sk_buff * skb, const struct net_device * in, const struct net_device * out) {
	#ifdef DEBUG_DUMP
	Log("*** #%d %c len=%d(%d) %s->%s ***\n", 	
		pktCount,
		hooknum == HOOK_UPLINK ? 'U' : 'D',
		(int)skb->len, 
		(int)skb->len + 14, 
		in==NULL ? "null" : in->name, 
		out==NULL ? "null" : out->name
	);
	#endif

	/*
	//(int)(skb->tail - skb->data) always equals to skb->len	
	if (skb->tail - skb->data != skb->len) {
		ReportError("!!! SIZE NOT MATCH %d %d %d !!!", (int)skb->data_len, (int)skb->len, (int)(skb->tail - skb->data));
	}
	*/
	
	IPv4_INFO info;
	if (!IsIPv4(skb, &info)) {
		//Log("\t(not IPv4 packet)\n");
		return 0;
	}
	
	if (info.protocol == PROT_TCP || info.protocol == PROT_UDP) {
		#ifdef DEBUG_DUMP
		Log("\t%s %s:%d->%s:%d (%d B)\n",
			info.protocol == PROT_TCP ? "TCP" : "UDP",
			ConvertDWORDToIP(info.srcIP),
			(int)info.srcPort,
			ConvertDWORDToIP(info.dstIP),
			(int)info.dstPort,
			info.payloadLen
		);
		#endif
	} else {
		#ifdef DEBUG_DUMP
		Log("\tProt=%d %s->%s (%d B)\n",
			(int)info.protocol,
			ConvertDWORDToIP(info.srcIP),
			ConvertDWORDToIP(info.dstIP),
			info.payloadLen
		);
		#endif
		return 0;
	}
		
	//only handle TCP and UDP
	if (info.protocol == PROT_TCP) {
		if (hooknum == HOOK_UPLINK) { //UPLINK

			/*
			//option 1: only route traffic not destined to the middlebox to CMAT
			//if (info.dstIP == rIP && info.dstPort != 6001 && info.dstPort != 6002) return 0;
	
			//option 2: only route port 6001/6002 traffic destined to the middlebox to CMAT (used to evaluate HTTP/SPDY proxy in the paper)
			if (info.dstIP != rIP) return 0;
			if (info.dstPort != 6001 && info.dstPort != 443) return 0;	//HTTP proxy
			*/

			if (!forwardedPorts[info.dstPort]) return 0;

			int bSYN;
			bSYN = info.tcpFlags & TCPFLAG_SYN;
			
			/*
			if (bSYN) {
				if (GetTCPMSS(skb, &info) == MAGIC_MSS_VALUE) {
					srcPort2NoModify[info.srcPort] = 1;
				} else {
					srcPort2NoModify[info.srcPort] = 0;
				}
			}
			
			if (srcPort2NoModify[info.srcPort]) return 0;
			*/
			
			#ifdef USE_TEST_SERVER
			if (info.dstIP == tIP) {							
			#endif
				*(DWORD *)(skb->data + 16) = localHost; //dstIP
				*(WORD *)(skb->data + info.ipHeaderLen + 2) = localProxyPort; //dstPort
										
				if (bSYN) {					
					AddIPOptionForSYN(skb, &info);
					
					if (srcPort2serverIP[info.srcPort] != 0) {
						Log("*** DUPLICATE PORT!!! ***\n");
					}
					
					srcPort2serverPort[info.srcPort] = info.dstPort;
					srcPort2serverIP[info.srcPort] = info.dstIP;
				}
							
				UpdateTCPIPChecksum(hooknum, skb, &info);						
				#ifdef DEBUG_DUMP
				Log("\t ### DstIP/Port changed to %s/%d\n", ConvertDWORDToIP(localHost), (int)LOCAL_PROXY_PORT);
				#endif
				
				return 1;
			#ifdef USE_TEST_SERVER		
			}
			#endif
		} else { //DOWNLINK
			//if (srcPort2NoModify[info.dstPort]) return 0;
			
			/*
			if (info.srcIP !=  rIP) return 0;
			if (info.srcIP == rIP && info.srcPort != 6001 && info.srcPort != 6002) return 0;
			*/
			
			if (info.srcIP == localHost && info.srcPort == LOCAL_PROXY_PORT) {	
				
				DWORD svrIP = srcPort2serverIP[info.dstPort];
				WORD svrPort = srcPort2serverPort[info.dstPort];
				
				*(DWORD *)(skb->data + 12) = svrIP;	//srcIP
				*((WORD *)(skb->data + info.ipHeaderLen)) = ReverseWORD(svrPort); //srcPort
						
				UpdateTCPIPChecksum(hooknum, skb, &info);				
				#ifdef DEBUG_DUMP
				Log("\t ### SrcIP/Port changed to %s/%d\n", ConvertDWORDToIP(svrIP), (int)svrPort);
				#endif
				
				return 1;
			}
		} 
	} else {  //UDP
		//TODO: currently do nothing for UDP
	}
	
	return 0;
}


/* Function prototype in <linux/netfilter> */
unsigned int main_hook(const struct nf_hook_ops *ops,  
                  struct sk_buff * skb,
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn)(struct sk_buff*))
{

	unsigned hooknum = ops->hooknum;

	if (!skb) return NF_ACCEPT;
	if (skb->pkt_type != PACKET_HOST) return NF_ACCEPT;	
	
	//TODO: serious performance issue
	/*
	if (skb_is_nonlinear(skb)) {		
		if (skb_linearize(skb) != 0) return NF_DROP;
	}
	*/
		
	pktCount++;
	int bMod = 0;
		
	if (hooknum == HOOK_UPLINK && !strcmp(out->name, fwdInterface)) {
		bMod = ModifyPacket(hooknum, skb, in, out);
	} else if (hooknum == HOOK_DOWNLINK && !strcmp(in->name, "lo")) {
		bMod = ModifyPacket(hooknum, skb, in, out);
	} else {
		goto NO_MOD;
	}
			
	if (bMod) {
		if (hooknum == HOOK_UPLINK) {
			static struct net_device * pLO = NULL;
			if (pLO == NULL) pLO = dev_get_by_name(&init_net, "lo");				
			skb->dev = pLO;
						
			dev_hard_header(skb, skb->dev, ETH_P_IP, NULL //dest MAC addr
				, NULL //skb->dev->dev_addr //my MAC addr
				, skb->dev->addr_len
			);
			
			//no TCP checksum
			skb->ip_summed = CHECKSUM_UNNECESSARY;
				
			//Important: force to update the routing info
			ip_route_me_harder(skb, RTN_LOCAL);
						
					
			/*
			////////////////////////// Dumping dst_entry //////////////////////	
			struct rtable * rt = skb_rtable(skb);
			Log("RT: src=%s dst=%s, gateway=%s, spec_dst=%s\n",
				ConvertDWORDToIP(rt->rt_src),
				ConvertDWORDToIP(rt->rt_dst),
				ConvertDWORDToIP(rt->rt_gateway),
				ConvertDWORDToIP(rt->rt_spec_dst)
			);			
			////////////////////////// Dumping dst_entry //////////////////////
			*/
			
			int r = dev_queue_xmit(skb); //no need for kfree_skb(skb);
			if (r < 0) ReportError("dev_queue_xmit returns %d", r);			
			return NF_STOLEN;
		} else {
			goto NO_MOD; 
		}	
	}
		
NO_MOD:
	
	return NF_ACCEPT;
}



int init_module()
{
	#ifdef USE_TEST_SERVER
	tIP = ConvertIPToDWORD(testServerIP);
	Log("Test Server IP = %s\n", ConvertDWORDToIP(tIP));
	#endif

	rIP = ConvertIPToDWORD(remoteProxyIP);
	Log("Remote Proxy IP = %s\n", ConvertDWORDToIP(rIP));
	
	localHost = ConvertIPToDWORD(LOCAL_PROXY_IP);
	localProxyPort = ReverseWORD(LOCAL_PROXY_PORT);

	Log("Interface name = %s\n", fwdInterface);
		
	int i;
	for (i=0; i<65535; i++) {
		srcPort2serverPort[i] = 0;
		srcPort2serverIP[i] = 0;
		forwardedPorts[i] = 0;
		//srcPort2NoModify[i] = 0;
	}

	ParsePortList();
		
	netfilter_ops_in.hook                   =       main_hook;
	netfilter_ops_in.pf                     =       PF_INET;
	netfilter_ops_in.hooknum                =       HOOK_UPLINK;	//out to interface
	netfilter_ops_in.priority               =       NF_IP_PRI_MANGLE;	
	netfilter_ops_out.hook                  =       main_hook;
	netfilter_ops_out.pf                    =       PF_INET;
	netfilter_ops_out.hooknum               =       HOOK_DOWNLINK; //in from interface
	netfilter_ops_out.priority              =       NF_IP_PRI_MANGLE; 
	nf_register_hook(&netfilter_ops_in); /* register NF_IP_PRE_ROUTING hook */
	nf_register_hook(&netfilter_ops_out); /* register NF_IP_POST_ROUTING hook */
	return 0;
}

void cleanup_module()
{
	nf_unregister_hook(&netfilter_ops_in); 
	nf_unregister_hook(&netfilter_ops_out);
}


