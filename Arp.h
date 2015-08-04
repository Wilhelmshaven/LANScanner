#pragma once

//28字节ARP帧结构
class arp_head
{
public:
	unsigned short hardware_type;    //硬件类型,2字节
	unsigned short protocol_type;    //协议类型，2字节
	unsigned char hardware_add_len;  //硬件地址长度，1字节
	unsigned char protocol_add_len;  //协议地址长度，1字节
	unsigned short operation_field;  //操作字段，2字节
	unsigned char source_mac_add[6]; //源mac地址，6字节
	unsigned long source_ip_add;     //源ip地址，4字节
	unsigned char dest_mac_add[6];   //目的mac地址，6字节
	unsigned long dest_ip_add;       //目的ip地址，4字节

public:
	arp_head(){};
	~arp_head(){};
};

//14字节以太网帧结构
class ethernet_head
{
public:
	unsigned char dest_mac_add[6];    //目的mac地址，6字节
	unsigned char source_mac_add[6];  //源mac地址，6字节
	unsigned short type;              //帧类型，2字节

public:
	ethernet_head(){};
	~ethernet_head(){};
};

//arp包结构
class arp_packet
{
public:
	ethernet_head ed;
	arp_head ah;
	//unsigned char padding[18];
	//unsigned char fcs[4];

public:
	arp_packet(){};
	~arp_packet(){};

};

//封装参数表，线程需要
class sparam
{
public:
	pcap_t *adhandle;
	char *ip;
	char *netmask;
	HWND myDlg;

public:
	sparam(){};
	~sparam(){};
};

//设备类
class Device
{
public:
	pcap_if_t *alldevs;   //设备列表
	pcap_t *adhandle;
	char *errbuf;
	char *ip_addr;        //自己的IP
	char *ip_netmask;     //自己的子网掩码
	char *mac;            //自己的MAC地址
	int select;           //选中的网卡编号
	int tmp;              //本机标记

public:
	Device();  //构造函数，并获取本机设备列表
	~Device(); //析构函数，并释放本机设备列表及关闭打开的网卡

	//将数字类型的IP地址转换成字符串类型的
	char *iptos(u_long in, int type)//type:1 for IP
	{
		char *ipstr = new char[16];
		u_char *p;
		p = (u_char *)&in;//这部分通过指针类型的改变实现了转换过程
		sprintf(ipstr, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
		if (type == 1)tmp = p[3];
		return ipstr;
	}

	void GetInfo(pcap_if_t *d, char *ip_addr, char *ip_netmask);//获得自己的IP和子网掩码
	int OpenDevice(pcap_if_t *d);//打开设备
	void findCurrentDevice(int option);//根据获得的被选中的设备名字去获取该网卡信息（IP、掩码）
};