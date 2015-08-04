#pragma once

//28�ֽ�ARP֡�ṹ
class arp_head
{
public:
	unsigned short hardware_type;    //Ӳ������,2�ֽ�
	unsigned short protocol_type;    //Э�����ͣ�2�ֽ�
	unsigned char hardware_add_len;  //Ӳ����ַ���ȣ�1�ֽ�
	unsigned char protocol_add_len;  //Э���ַ���ȣ�1�ֽ�
	unsigned short operation_field;  //�����ֶΣ�2�ֽ�
	unsigned char source_mac_add[6]; //Դmac��ַ��6�ֽ�
	unsigned long source_ip_add;     //Դip��ַ��4�ֽ�
	unsigned char dest_mac_add[6];   //Ŀ��mac��ַ��6�ֽ�
	unsigned long dest_ip_add;       //Ŀ��ip��ַ��4�ֽ�

public:
	arp_head(){};
	~arp_head(){};
};

//14�ֽ���̫��֡�ṹ
class ethernet_head
{
public:
	unsigned char dest_mac_add[6];    //Ŀ��mac��ַ��6�ֽ�
	unsigned char source_mac_add[6];  //Դmac��ַ��6�ֽ�
	unsigned short type;              //֡���ͣ�2�ֽ�

public:
	ethernet_head(){};
	~ethernet_head(){};
};

//arp���ṹ
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

//��װ�������߳���Ҫ
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

//�豸��
class Device
{
public:
	pcap_if_t *alldevs;   //�豸�б�
	pcap_t *adhandle;
	char *errbuf;
	char *ip_addr;        //�Լ���IP
	char *ip_netmask;     //�Լ�����������
	char *mac;            //�Լ���MAC��ַ
	int select;           //ѡ�е��������
	int tmp;              //�������

public:
	Device();  //���캯��������ȡ�����豸�б�
	~Device(); //�������������ͷű����豸�б��رմ򿪵�����

	//���������͵�IP��ַת�����ַ������͵�
	char *iptos(u_long in, int type)//type:1 for IP
	{
		char *ipstr = new char[16];
		u_char *p;
		p = (u_char *)&in;//�ⲿ��ͨ��ָ�����͵ĸı�ʵ����ת������
		sprintf(ipstr, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
		if (type == 1)tmp = p[3];
		return ipstr;
	}

	void GetInfo(pcap_if_t *d, char *ip_addr, char *ip_netmask);//����Լ���IP����������
	int OpenDevice(pcap_if_t *d);//���豸
	void findCurrentDevice(int option);//���ݻ�õı�ѡ�е��豸����ȥ��ȡ��������Ϣ��IP�����룩
};