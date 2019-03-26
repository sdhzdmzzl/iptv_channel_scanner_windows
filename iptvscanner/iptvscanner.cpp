// iptvscanner.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <winsock2.h>
#include <string.h>
#include <pcap.h>
#include <iostream>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")
using namespace std;
char nicname[1024] = { 0 };

struct udphdr
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
};
BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
int iptvscan(unsigned int ip)

{
	char errBuf[PCAP_ERRBUF_SIZE];
	SOCKET s; /*套接字文件描述符*/
	int err = -1;
	ip = htonl(ip);
	s = socket(AF_INET, SOCK_DGRAM, 0); /*建立套接字*/
	if (s == -1)
	{
		printf("unable to create socket\n");
		return -1;
	}

	struct ip_mreq mreq;                           /*加入多播组*/
	mreq.imr_multiaddr.s_addr = ip;         /*多播地址*/
	mreq.imr_interface.s_addr = htonl(INADDR_ANY); /*网络接口为默认*/

	err = setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char *)&mreq, sizeof(mreq));
	if (err < 0)
	{
		printf("unable to setsockopt\n");
		return -1;
	}

	pcap_t *device = pcap_open_live(nicname, 65535, 1, 1, errBuf); //1ms超时，下边会留出时间填充数据包

	if (!device)
	{
		cout << "error: pcap_open_live():" << errBuf << endl;
		closesocket(s);
		return -1;
	}
	char strfilter[64] = "udp and host ";
	char *strip = strfilter + strlen("udp and host ");
	inet_ntop(AF_INET, &ip, strip, 16);
	/* construct a filter */
	struct bpf_program filter;
	pcap_compile(device, &filter, strfilter, 1, 0);
	pcap_setfilter(device, &filter);

	Sleep(1500);
	struct pcap_pkthdr packet;
	const u_char *pktStr = pcap_next(device, &packet);
	if (pktStr)
	{
		struct udphdr *udphdr = NULL;
		udphdr = (struct udphdr *)(pktStr + 14 + 20);
		printf("#EXTINF:-1,%s:%d\nrtp://%s:%d\n", strip, ntohs(udphdr->dport), strip, ntohs(udphdr->dport));

	}
	pcap_close(device);

	err = setsockopt(s, IPPROTO_IP, IP_DROP_MEMBERSHIP, (const char *)&mreq, sizeof(mreq));
	if (err < 0)
	{
		closesocket(s);
		return -1;
	}
	closesocket(s);
	return 0;
}

int main(int argc, char *argv[])
{

	pcap_if_t *alldevs;

	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	int inum;
	if (argc != 3)
	{
		cout << "usage:" << endl
			<< "\t" << argv[0] << " \"start of ip\" \"end of ip\" " << endl;
		cout << "\t eg.. " << argv[0] << " 239.3.1.1 239.3.1.254" << endl;
		return -1;
	}
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	/* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
	wVersionRequested = MAKEWORD(2, 2);

	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0) {
		/* Tell the user that we could not find a usable */
		/* Winsock DLL.                                  */
		printf("WSAStartup failed with error: %d\n", err);
		return 1;
	}
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 打印列表 */
	pcap_if_t *d;
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	cout << "Enter the interface number (1-%d):";
	cin >> inum;

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}
	cout << "#EXTM3U name=\"bj-unicom-iptv\"" << endl;
	/* 跳转到选中的适配器 */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++)
		;
	strncpy_s(nicname, d->name, sizeof(nicname));
	pcap_freealldevs(alldevs);
	unsigned int ipstart = 0, ipend = 0;
	inet_pton(AF_INET, argv[1], &ipstart);
	inet_pton(AF_INET, argv[2], &ipend);
	ipstart = ntohl(ipstart);
	ipend = ntohl(ipend);
	for (unsigned int ip = ipstart; ip <= ipend; ip++)
	{
		iptvscan(ip);
	}
}

