#include "stdafx.h"
#include "Arp.h"

Device::Device()
{
	//初始化变量
	ip_addr = new char[16];
	ip_netmask = new char[16];
	mac = new char[17];
	errbuf = new char[PCAP_ERRBUF_SIZE];
	select = 0;
	adhandle = NULL;

	/* 获取本机设备列表*/
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)exit(1);
}

Device::~Device()
{
	if (adhandle != NULL) pcap_close(adhandle); //关闭打开的网卡
	pcap_freealldevs(alldevs);    //释放设备列表
}

void Device::findCurrentDevice(int option)
{
	//确定哪块网卡被选中，并打开它
	pcap_if_t *d;
	
	d = alldevs;
	for (int i = 0; i < option; i++)d = d->next;//跳转到指定网卡

	OpenDevice(d);                     //打开网卡
	GetInfo(d, ip_addr, ip_netmask);   //获得自己的IP与掩码
}

//获得自己的IP与掩码
void Device::GetInfo(pcap_if_t *d, char *ip_addr, char *ip_netmask)
{
	pcap_addr_t *a;
	for (a = d->addresses; a; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)//internetwork: UDP, TCP, etc. 即取IP包
		{
			if (a->addr)
			{
				char *ipstr;
				ipstr = iptos(((sockaddr_in *)a->addr)->sin_addr.s_addr, 1);
				memcpy(ip_addr, ipstr, 16);
			}
			if (a->netmask)
			{
				char *netmaskstr;
				netmaskstr = iptos(((sockaddr_in *)a->netmask)->sin_addr.s_addr, 2);
				memcpy(ip_netmask, netmaskstr, 16);
			}
		}
	}
}

//打开设备
int Device::OpenDevice(pcap_if_t *d)
{
	if ((adhandle = pcap_open(d->name,          // 设备名
		65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式，以保证抓到ARP包
		1,             /*读取超时时间，单位为毫秒，捕捉数据包的时候，延迟一定的时间，然后再调用内核中的程序，
					   这样效率较高。0表示没有延迟，没有包到达的时候永不返回。-1表示立即返回。*/
					   NULL,             // 远程机器验证
					   errbuf            // 错误缓冲池
					   )) == NULL)
	{
		pcap_freealldevs(alldevs);//释放设备列表
		return -1;
	}
	else return 0;
}