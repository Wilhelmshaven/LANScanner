#include "stdafx.h"
#include "Arp.h"

Device::Device()
{
	//��ʼ������
	ip_addr = new char[16];
	ip_netmask = new char[16];
	mac = new char[17];
	errbuf = new char[PCAP_ERRBUF_SIZE];
	select = 0;
	adhandle = NULL;

	/* ��ȡ�����豸�б�*/
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)exit(1);
}

Device::~Device()
{
	if (adhandle != NULL) pcap_close(adhandle); //�رմ򿪵�����
	pcap_freealldevs(alldevs);    //�ͷ��豸�б�
}

void Device::findCurrentDevice(int option)
{
	//ȷ���Ŀ�������ѡ�У�������
	pcap_if_t *d;
	
	d = alldevs;
	for (int i = 0; i < option; i++)d = d->next;//��ת��ָ������

	OpenDevice(d);                     //������
	GetInfo(d, ip_addr, ip_netmask);   //����Լ���IP������
}

//����Լ���IP������
void Device::GetInfo(pcap_if_t *d, char *ip_addr, char *ip_netmask)
{
	pcap_addr_t *a;
	for (a = d->addresses; a; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)//internetwork: UDP, TCP, etc. ��ȡIP��
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

//���豸
int Device::OpenDevice(pcap_if_t *d)
{
	if ((adhandle = pcap_open(d->name,          // �豸��
		65536,            // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ���Ա�֤ץ��ARP��
		1,             /*��ȡ��ʱʱ�䣬��λΪ���룬��׽���ݰ���ʱ���ӳ�һ����ʱ�䣬Ȼ���ٵ����ں��еĳ���
					   ����Ч�ʽϸߡ�0��ʾû���ӳ٣�û�а������ʱ���������ء�-1��ʾ�������ء�*/
					   NULL,             // Զ�̻�����֤
					   errbuf            // ���󻺳��
					   )) == NULL)
	{
		pcap_freealldevs(alldevs);//�ͷ��豸�б�
		return -1;
	}
	else return 0;
}