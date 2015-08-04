/*************************************************************
*   I declare that the assignment here submitted is original *
* except for source material explicitly acknowledged. I also *
* acknowledge that I am aware of University policy and       *
* regulations on honesty in academic work, and of the        *
* disciplinary guidelines and procedures applicable to       *
* breaches of such policy and regulations.                   *
*                                                            *
* Hongjie Li                    2014.10.19                   *
* Signature						Date                         *
*                                                            *
* ����   			            143020085211001              *
* Name						    Student ID                   *
*                                                            *
* CS400            	Advanced Windows Network Programming     *
* Course code	    Course title                             *
*************************************************************/
// LANScanner.cpp : ����Ӧ�ó������ڵ㡣

#include "stdafx.h"
#include "LANScanner.h"
#include "Arp.h"

// ������任��ʹ��WIN8���
#pragma comment(linker, "\"/manifestdependency:type='Win32'\
 name='Microsoft.Windows.Common-Controls' version='6.0.0.0'\
 processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ȫ�ֱ��� 
enum ARPDefine
{
	ETH_ARP = 0x0806,     // ��̫��֡���ͱ�ʾ�������ݵ����ͣ�����ARP�����Ӧ����˵�����ֶε�ֵΪx0806
	ARP_HARDWARE = 1,     // Ӳ�������ֶ�ֵΪ��ʾ��̫����ַ
	ETH_IP = 0x0800,      // Э�������ֶα�ʾҪӳ���Э���ַ����ֵΪx0800��ʾIP��ַ
	ARP_REQUEST = 1,
	ARP_REPLY = 2
};
enum CustomDefine
{
	MAX_LOADSTRING = 100
};

HINSTANCE hInst;								// ��ǰʵ��
TCHAR szTitle[MAX_LOADSTRING];					// �������ı�
TCHAR szWindowClass[MAX_LOADSTRING];			// ����������
Device myDevice;                                // �豸��

HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);   // ʹ���¼���������߳�ͬ��  
HANDLE hAgain = CreateEvent(NULL, TRUE, FALSE, NULL);   // Ĭ�ϰ�ȫ���ԣ��ֹ����ã���ʼΪδ��λ�ģ�δ���� 

//ARPING��ر���
BOOL flag = FALSE;
sparam sp;

// �˴���ģ���а����ĺ�����ǰ������: 
ATOM				MyRegisterClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	About(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK DlgProc(HWND hdlg, UINT msg, WPARAM wParam, LPARAM lParam);           // �Ӵ���
UINT SendArpPacket(LPVOID lpParameter);                                                // �հ�����
UINT AnalyzePacket(LPVOID lpParameter);                                                // ��������
BOOL AddListViewItems(HWND hwndListView, char *ip_add, char *mac_add, char *delay);    // �ѽ�������ListView��

HANDLE sendThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SendArpPacket, NULL, 0, NULL);  // �հ��߳�
HANDLE recvThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AnalyzePacket, NULL, 0, NULL);  // �����߳�

/*============================== WinMain ==============================*/
int APIENTRY _tWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine, _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO:  �ڴ˷��ô���
    MSG msg;
    HACCEL hAccelTable;

    // ��ʼ��ȫ���ַ���
    LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadString(hInstance, IDC_LANSCANNER, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // ִ��Ӧ�ó����ʼ��: 
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_LANSCANNER));

    // ����Ϣѭ��: 
    while (GetMessage(&msg, NULL, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}

// ע�ᴰ����
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEX wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style			= CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc	= WndProc;
    wcex.cbClsExtra		= 0;
    wcex.cbWndExtra		= 0;
    wcex.hInstance		= hInstance;
    wcex.hIcon			= LoadIcon(hInstance, MAKEINTRESOURCE(IDI_LANSCANNER));
    wcex.hCursor		= LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground	= (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName	= MAKEINTRESOURCE(IDC_LANSCANNER);
    wcex.lpszClassName	= szWindowClass;
    wcex.hIconSm		= LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassEx(&wcex);
}

// ��ȫ�ֱ����б���ʵ���������������ʾ�����򴰿ڡ�
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   HWND hWnd;

   hInst = hInstance; // ��ʵ������洢��ȫ�ֱ�����

   // �����ڲ��ɱ��С��������
   hWnd = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
      CW_USEDEFAULT, 0, 540, 630, NULL, NULL, hInstance, NULL);
  
   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

// ���������ڵ���Ϣ
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    int wmId, wmEvent;
    HWND myhdlg;

    switch (message)
    {
    case WM_CREATE:
    {
        // �����ӶԻ��򲢽�����Ϊ������
        myhdlg = CreateDialog(hInst, MAKEINTRESOURCE(IDD_FORMVIEW), hWnd, (DLGPROC)DlgProc);
        ShowWindow(myhdlg, SW_SHOW);// ��ʾ�Ի���
    }
    case WM_COMMAND:
        wmId = LOWORD(wParam);
        wmEvent = HIWORD(wParam);

        // �����˵�ѡ��: 
        switch (wmId)
        {
            // ����ɨ��˵�ѡ��
        case IDM_RUNSCAN:
        {
            if (flag == TRUE)
            {
                // ���߳̿�ʼ��һ������
				SetEvent(hAgain);
            }

            flag = FALSE;  // �����Ʒ����û�ȥ�����������˵�û�и��ģ������в˵�ʧЧ
            break;
        }
            // ֹͣɨ�裺�ر��̣߳�������Ϣ
        case IDM_STOP:
			SetEvent(hEvent);
            break;
            // ����������Ϣ�˵�ѡ��
        case IDM_ABOUT:
            DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
            break;
            // �˳��˵�ѡ��
        case IDM_EXIT:
            DestroyWindow(hWnd);
            break;
        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
        }
        break;
    case WM_DESTROY:
		CloseHandle(sendThread);
		CloseHandle(recvThread);
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// �����ڡ������Ϣ�������
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

// ����Ի�����Ϣ  
INT_PTR CALLBACK DlgProc(HWND hdlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    int wmId, wmEvent;
    HWND hListview = GetDlgItem(hdlg, IDC_LIST3);       // ListView
    HWND hWndComboBox = GetDlgItem(hdlg, IDC_COMBO1);   // ComboBox
    HWND EditBox;                                       // EditBox
    
    switch (msg)
    {
    case WM_INITDIALOG:
    {
        // ���Listview����������������

        // ����ListView����  
        LVCOLUMN lvc;
        lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

        lvc.pszText = "IP Address";//�б���  
        lvc.cx = 140;//�п�  
        lvc.iSubItem = 0;//������������һ��������  
        lvc.fmt = LVCFMT_CENTER;
        ListView_InsertColumn(hListview, 0, &lvc);

        lvc.pszText = "MAC Address";
        lvc.cx = 160;
        lvc.iSubItem = 1;//��������  
        lvc.fmt = LVCFMT_CENTER;
        ListView_InsertColumn(hListview, 1, &lvc);

        lvc.pszText = "Arp Time";
        lvc.cx = 100;
        lvc.iSubItem = 2;
        lvc.fmt = LVCFMT_CENTER;
        ListView_InsertColumn(hListview, 2, &lvc);

        // �������б������Ŀ
        pcap_if_t *d;
        for (d = myDevice.alldevs; d; d = d->next)
        {
            SendMessage(hWndComboBox, CB_ADDSTRING, 0, (LPARAM)d->description);
        }

        return 0;
    }// WM_INITDIALOG

    case WM_COMMAND:
    {
        wmId = LOWORD(wParam);
        wmEvent = HIWORD(wParam);

        // ����ؼ���Ϣ
        switch (wmEvent)
        {
        case CBN_SELCHANGE:
            int Selected = 0;

            Selected = (int)SendMessage(hWndComboBox, CB_GETCURSEL, 0, 0);  // ���ѡ�е�ѡ����

            myDevice.findCurrentDevice(Selected);                           // ���ݻ�õı�ѡ�е��豸����ȥ��ȡ��������Ϣ��IP�����룩
            SendMessage(hWndComboBox, CB_SETCURSEL, (WPARAM)Selected, 0);   // ��ʾѡ�е�����

            // ��ʾ����IP
            EditBox = GetDlgItem(hdlg, IDC_EDIT_IP);
            SendMessage(EditBox, EM_SETREADONLY, 0, 0);
            SendMessage(EditBox, WM_SETTEXT, 0, (LPARAM)myDevice.ip_addr);

            // ��ʾ��������
            EditBox = GetDlgItem(hdlg, IDC_EDIT_MASK);
            SendMessage(EditBox, EM_SETREADONLY, 0, 0);
            SendMessage(EditBox, WM_SETTEXT, 0, (LPARAM)myDevice.ip_netmask);

            // �������ݰ�������������
            sp.adhandle = myDevice.adhandle;
            sp.ip = myDevice.ip_addr;
            sp.netmask = myDevice.ip_netmask;
            sp.myDlg = hdlg;

            // �����Ҫ��յ���Ϣ������һ�ε�ɨ������
            char *empty = "�ȴ�ץ������";
            SendMessage(hListview, LVM_DELETEALLITEMS, 0, 0);
            EditBox = GetDlgItem(hdlg, IDC_EDIT_MAC);
            SendMessage(EditBox, WM_SETTEXT, 0, (LPARAM)empty);
            EditBox = GetDlgItem(hdlg, IDC_EDIT_GATEIP);
            SendMessage(EditBox, WM_SETTEXT, 0, (LPARAM)empty);
            EditBox = GetDlgItem(hdlg, IDC_EDIT_GATEMAC);
            SendMessage(EditBox, WM_SETTEXT, 0, (LPARAM)empty);

            flag = TRUE;                       // ʹ�����в˵���Ч
            break;
        }// wmEvent
    }// WM_COMMAND
    }// msg

    return (INT_PTR)FALSE;
}

/* ������������п��ܵ�IP��ַ����ARP������߳� */
UINT SendArpPacket(LPVOID lpParameter)
{
	while (true)
	{
		WaitForSingleObject(hAgain, INFINITE);

		sparam *spara = &sp;
		pcap_t *adhandle = spara->adhandle;

		char *ip = spara->ip;                            // �Լ���IP
		char *netmask = spara->netmask;                  // �Լ���NETMASK
		unsigned char *sendbuf = new unsigned char[42];  // arp���ṹ��С�����ﲻ����padding��fcs
		ethernet_head eh;
		arp_head ah;

		// �������
		eh.type = htons(ETH_ARP);
		memset(eh.dest_mac_add, 0xff, 6);                // MAC�Ĺ㲥��ַΪFF-FF-FF-FF-FF-FF
		memset(ah.dest_mac_add, 0xff, 6);                // ֻ�ǳ�ʼ��
		ah.hardware_type = htons(ARP_HARDWARE);
		ah.protocol_type = htons(ETH_IP);
		ah.hardware_add_len = 6;
		ah.protocol_add_len = 4;
		inet_pton(AF_INET, ip, &ah.source_ip_add);       // ���󷽵�IP��ַΪ�����IP��ַ	
		ah.operation_field = htons(ARP_REQUEST);

		// ��������ڹ㲥����arp��
		unsigned long myip, mynetmask;
		inet_pton(AF_INET, ip, &myip);
		inet_pton(AF_INET, netmask, &mynetmask);
		unsigned long dest_ip = htonl((myip&mynetmask));

		for (int i = 0; i < 256; i++)                  // ���������е�IP
		{
			ah.dest_ip_add = htonl(dest_ip + i);       // ��iֵ�仯��������

			// �����õ����ݰ�װ�뻺��
			memset(sendbuf, 0, sizeof(sendbuf));
			memcpy(sendbuf, &eh, sizeof(eh));
			memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));

			pcap_sendpacket(adhandle, sendbuf, 42);    // ����

			//Sleep(10);                                 // ��������Ϣһ���
		}

		// ����Event֪ͨ�հ��̷߳����ѽ���
		Sleep(1000);// ȷ���հ�����
		SetEvent(hEvent);
		ResetEvent(hAgain);
		Beep(440, 200);
	}

    return 0;
}

/* �������������ݰ���ȡ�������IP��ַ */
UINT AnalyzePacket(LPVOID lpParameter)
{
	while (true)
	{
		WaitForSingleObject(hAgain, INFINITE);

		sparam *spara = &sp;
		pcap_t *adhandle = spara->adhandle;
		int res;
		char *mac_add = new char[];
		char *ip_add = new char[];
		char *delay = new char[];
		pcap_pkthdr * pkt_header;
		const u_char * pkt_data;
		double delayTime;

		HWND hwndListView = GetDlgItem(spara->myDlg, IDC_LIST3);
		HWND EditBox;
		HWND Dialog = spara->myDlg;

		// ��Ƿ�ȥ���ظ��İ�
		int mark[256];
		memset(mark, 0, sizeof(mark));
		int tmp;

		while (true)
		{
			if ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) > 0)  // ʹ�÷ǻص������������ݰ�
			{
				if (*(unsigned short *)(pkt_data + 12) == htons(ETH_ARP))    // �ж�ARP���ĵ�13,14λ��Type���Ƿ����0x0806��Ŀ�����˳�ARP��			
				{
					arp_packet *recv = (arp_packet *)pkt_data;               // ������ת��ARP���ṹ
					if (recv->ah.operation_field == htons(ARP_REPLY))        // �жϲ�����λ�Ƿ���ARP_REPLY�����˳�ARPӦ���
					{
						// ��ʽ��IP�������
						sprintf(ip_add, "%d.%d.%d.%d", recv->ah.source_ip_add & 255, recv->ah.source_ip_add >> 8 & 255,
							recv->ah.source_ip_add >> 16 & 255, recv->ah.source_ip_add >> 24 & 255);
						// ��ʽ��MAC�������
						sprintf(mac_add, "%02X-%02X-%02X-%02X-%02X-%02X", recv->ah.source_mac_add[0],
							recv->ah.source_mac_add[1], recv->ah.source_mac_add[2], recv->ah.source_mac_add[3],
							recv->ah.source_mac_add[4], recv->ah.source_mac_add[5]);
						// �����ӳ�ʱ�䲢��ʽ��
						delayTime = (double)pkt_header->ts.tv_usec / 1000;  // ts.tv_usec�ĵ�λ��΢�룬ת�ɺ������
						sprintf(delay, "%3.3fms", delayTime);               // ����ʱ�䲿���������ʾ�����������ָ���Ϊ3

						// ������ԭ�г�������ϼ���ΪListView�����ĳ���
						tmp = (recv->ah.source_ip_add >> 24 & 255);//�±�
						if (mark[tmp] == 0)
						{
							AddListViewItems(hwndListView, ip_add, mac_add, delay);
							mark[tmp] = 1;
						}

						// ����Լ���IP
						if (tmp == myDevice.tmp)
						{
							EditBox = GetDlgItem(spara->myDlg, IDC_EDIT_MAC);
							SendMessage(EditBox, EM_SETREADONLY, 0, 0);
							SendMessage(EditBox, WM_SETTEXT, 0, (LPARAM)mac_add);
						}

						// ���������Ϣ������������Ϊ����ĩλ��1������254
						if (tmp == 1 || tmp == 254)
						{
							EditBox = GetDlgItem(spara->myDlg, IDC_EDIT_GATEIP);
							SendMessage(EditBox, EM_SETREADONLY, 0, 0);
							SendMessage(EditBox, WM_SETTEXT, 0, (LPARAM)ip_add);

							EditBox = GetDlgItem(spara->myDlg, IDC_EDIT_GATEMAC);
							SendMessage(EditBox, EM_SETREADONLY, 0, 0);
							SendMessage(EditBox, WM_SETTEXT, 0, (LPARAM)mac_add);
						}
					}
				}
			}

			// �յ������̵߳��¼��������ץ������������������Ҫ�����򶼲����ˡ���
			if (WaitForSingleObject(hEvent, 0) == WAIT_OBJECT_0)break;
		}

		Beep(880, 200);  // ��һ��������
		MessageBox(NULL, "��̽������", "��ʾ", MB_OK);
		ResetEvent(hEvent);
	}
    return 0;
}

BOOL AddListViewItems(HWND hwndListView, char *ip_add, char *mac_add, char *delay)
{
    LVITEM lvi;
    ZeroMemory(&lvi, sizeof(lvi));

    // ��Ч����
    lvi.mask = LVIF_TEXT | LVIF_PARAM | LVIF_STATE;

    // ����ı��ͳ���
    lvi.pszText = ip_add;
    lvi.cchTextMax = lstrlen(lvi.pszText) + 1;

    // ������
    ListView_InsertItem(hwndListView, &lvi);
    ListView_SetItemText(hwndListView, 0, 1, mac_add);
    ListView_SetItemText(hwndListView, 0, 2, delay);

    return TRUE;
}