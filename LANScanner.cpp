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
* 李宏杰   			            143020085211001              *
* Name						    Student ID                   *
*                                                            *
* CS400            	Advanced Windows Network Programming     *
* Course code	    Course title                             *
*************************************************************/
// LANScanner.cpp : 定义应用程序的入口点。

#include "stdafx.h"
#include "LANScanner.h"
#include "Arp.h"

// 界面风格变换：使用WIN8风格
#pragma comment(linker, "\"/manifestdependency:type='Win32'\
 name='Microsoft.Windows.Common-Controls' version='6.0.0.0'\
 processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// 全局变量 
enum ARPDefine
{
	ETH_ARP = 0x0806,     // 以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
	ARP_HARDWARE = 1,     // 硬件类型字段值为表示以太网地址
	ETH_IP = 0x0800,      // 协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
	ARP_REQUEST = 1,
	ARP_REPLY = 2
};
enum CustomDefine
{
	MAX_LOADSTRING = 100
};

HINSTANCE hInst;								// 当前实例
TCHAR szTitle[MAX_LOADSTRING];					// 标题栏文本
TCHAR szWindowClass[MAX_LOADSTRING];			// 主窗口类名
Device myDevice;                                // 设备类

HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);   // 使用事件对象进行线程同步  
HANDLE hAgain = CreateEvent(NULL, TRUE, FALSE, NULL);   // 默认安全属性，手工重置，初始为未置位的，未命名 

//ARPING相关变量
BOOL flag = FALSE;
sparam sp;

// 此代码模块中包含的函数的前向声明: 
ATOM				MyRegisterClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	About(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK DlgProc(HWND hdlg, UINT msg, WPARAM wParam, LPARAM lParam);           // 子窗口
UINT SendArpPacket(LPVOID lpParameter);                                                // 收包方法
UINT AnalyzePacket(LPVOID lpParameter);                                                // 发包方法
BOOL AddListViewItems(HWND hwndListView, char *ip_add, char *mac_add, char *delay);    // 把结果输出到ListView中

HANDLE sendThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SendArpPacket, NULL, 0, NULL);  // 收包线程
HANDLE recvThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AnalyzePacket, NULL, 0, NULL);  // 发包线程

/*============================== WinMain ==============================*/
int APIENTRY _tWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine, _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO:  在此放置代码
    MSG msg;
    HACCEL hAccelTable;

    // 初始化全局字符串
    LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadString(hInstance, IDC_LANSCANNER, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // 执行应用程序初始化: 
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_LANSCANNER));

    // 主消息循环: 
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

// 注册窗口类
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

// 在全局变量中保存实例句柄并创建和显示主程序窗口。
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   HWND hWnd;

   hInst = hInstance; // 将实例句柄存储在全局变量中

   // 主窗口不可变大小（锁定）
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

// 处理主窗口的消息
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    int wmId, wmEvent;
    HWND myhdlg;

    switch (message)
    {
    case WM_CREATE:
    {
        // 创建子对话框并将其作为主窗口
        myhdlg = CreateDialog(hInst, MAKEINTRESOURCE(IDD_FORMVIEW), hWnd, (DLGPROC)DlgProc);
        ShowWindow(myhdlg, SW_SHOW);// 显示对话框
    }
    case WM_COMMAND:
        wmId = LOWORD(wParam);
        wmEvent = HIWORD(wParam);

        // 分析菜单选择: 
        switch (wmId)
        {
            // 运行扫描菜单选项
        case IDM_RUNSCAN:
        {
            if (flag == TRUE)
            {
                // 让线程开始新一轮运作
				SetEvent(hAgain);
            }

            flag = FALSE;  // 将控制符设置回去，即若下拉菜单没有更改，则运行菜单失效
            break;
        }
            // 停止扫描：关闭线程，弹出消息
        case IDM_STOP:
			SetEvent(hEvent);
            break;
            // 弹出作者信息菜单选项
        case IDM_ABOUT:
            DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
            break;
            // 退出菜单选项
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

// “关于”框的消息处理程序。
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

// 处理对话框消息  
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
        // 添加Listview的列与下拉框数据

        // 设置ListView的列  
        LVCOLUMN lvc;
        lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

        lvc.pszText = "IP Address";//列标题  
        lvc.cx = 140;//列宽  
        lvc.iSubItem = 0;//子项索引，第一列无子项  
        lvc.fmt = LVCFMT_CENTER;
        ListView_InsertColumn(hListview, 0, &lvc);

        lvc.pszText = "MAC Address";
        lvc.cx = 160;
        lvc.iSubItem = 1;//子项索引  
        lvc.fmt = LVCFMT_CENTER;
        ListView_InsertColumn(hListview, 1, &lvc);

        lvc.pszText = "Arp Time";
        lvc.cx = 100;
        lvc.iSubItem = 2;
        lvc.fmt = LVCFMT_CENTER;
        ListView_InsertColumn(hListview, 2, &lvc);

        // 给下拉列表填充项目
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

        // 处理控件消息
        switch (wmEvent)
        {
        case CBN_SELCHANGE:
            int Selected = 0;

            Selected = (int)SendMessage(hWndComboBox, CB_GETCURSEL, 0, 0);  // 获得选中的选项编号

            myDevice.findCurrentDevice(Selected);                           // 根据获得的被选中的设备名字去获取该网卡信息（IP、掩码）
            SendMessage(hWndComboBox, CB_SETCURSEL, (WPARAM)Selected, 0);   // 显示选中的网卡

            // 显示本机IP
            EditBox = GetDlgItem(hdlg, IDC_EDIT_IP);
            SendMessage(EditBox, EM_SETREADONLY, 0, 0);
            SendMessage(EditBox, WM_SETTEXT, 0, (LPARAM)myDevice.ip_addr);

            // 显示子网掩码
            EditBox = GetDlgItem(hdlg, IDC_EDIT_MASK);
            SendMessage(EditBox, EM_SETREADONLY, 0, 0);
            SendMessage(EditBox, WM_SETTEXT, 0, (LPARAM)myDevice.ip_netmask);

            // 自制数据包：填充相关数据
            sp.adhandle = myDevice.adhandle;
            sp.ip = myDevice.ip_addr;
            sp.netmask = myDevice.ip_netmask;
            sp.myDlg = hdlg;

            // 清空需要清空的信息（如上一次的扫描结果）
            char *empty = "等待抓包……";
            SendMessage(hListview, LVM_DELETEALLITEMS, 0, 0);
            EditBox = GetDlgItem(hdlg, IDC_EDIT_MAC);
            SendMessage(EditBox, WM_SETTEXT, 0, (LPARAM)empty);
            EditBox = GetDlgItem(hdlg, IDC_EDIT_GATEIP);
            SendMessage(EditBox, WM_SETTEXT, 0, (LPARAM)empty);
            EditBox = GetDlgItem(hdlg, IDC_EDIT_GATEMAC);
            SendMessage(EditBox, WM_SETTEXT, 0, (LPARAM)empty);

            flag = TRUE;                       // 使得运行菜单生效
            break;
        }// wmEvent
    }// WM_COMMAND
    }// msg

    return (INT_PTR)FALSE;
}

/* 向局域网内所有可能的IP地址发送ARP请求包线程 */
UINT SendArpPacket(LPVOID lpParameter)
{
	while (true)
	{
		WaitForSingleObject(hAgain, INFINITE);

		sparam *spara = &sp;
		pcap_t *adhandle = spara->adhandle;

		char *ip = spara->ip;                            // 自己的IP
		char *netmask = spara->netmask;                  // 自己的NETMASK
		unsigned char *sendbuf = new unsigned char[42];  // arp包结构大小，这里不计入padding和fcs
		ethernet_head eh;
		arp_head ah;

		// 填充内容
		eh.type = htons(ETH_ARP);
		memset(eh.dest_mac_add, 0xff, 6);                // MAC的广播地址为FF-FF-FF-FF-FF-FF
		memset(ah.dest_mac_add, 0xff, 6);                // 只是初始化
		ah.hardware_type = htons(ARP_HARDWARE);
		ah.protocol_type = htons(ETH_IP);
		ah.hardware_add_len = 6;
		ah.protocol_add_len = 4;
		inet_pton(AF_INET, ip, &ah.source_ip_add);       // 请求方的IP地址为自身的IP地址	
		ah.operation_field = htons(ARP_REQUEST);

		// 向局域网内广播发送arp包
		unsigned long myip, mynetmask;
		inet_pton(AF_INET, ip, &myip);
		inet_pton(AF_INET, netmask, &mynetmask);
		unsigned long dest_ip = htonl((myip&mynetmask));

		for (int i = 0; i < 256; i++)                  // 遍历子网中的IP
		{
			ah.dest_ip_add = htonl(dest_ip + i);       // 随i值变化遍历子网

			// 把做好的数据包装入缓存
			memset(sendbuf, 0, sizeof(sendbuf));
			memcpy(sendbuf, &eh, sizeof(eh));
			memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));

			pcap_sendpacket(adhandle, sendbuf, 42);    // 发包

			//Sleep(10);                                 // 让网卡休息一会儿
		}

		// 设置Event通知收包线程发包已结束
		Sleep(1000);// 确保收包结束
		SetEvent(hEvent);
		ResetEvent(hAgain);
		Beep(440, 200);
	}

    return 0;
}

/* 分析截留的数据包获取活动的主机IP地址 */
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

		// 标记法去掉重复的包
		int mark[256];
		memset(mark, 0, sizeof(mark));
		int tmp;

		while (true)
		{
			if ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) > 0)  // 使用非回调方法捕获数据包
			{
				if (*(unsigned short *)(pkt_data + 12) == htons(ETH_ARP))    // 判断ARP包的第13,14位（Type）是否等于0x0806，目的是滤出ARP包			
				{
					arp_packet *recv = (arp_packet *)pkt_data;               // 把数据转成ARP包结构
					if (recv->ah.operation_field == htons(ARP_REPLY))        // 判断操作符位是否是ARP_REPLY，即滤出ARP应答包
					{
						// 格式化IP便于输出
						sprintf(ip_add, "%d.%d.%d.%d", recv->ah.source_ip_add & 255, recv->ah.source_ip_add >> 8 & 255,
							recv->ah.source_ip_add >> 16 & 255, recv->ah.source_ip_add >> 24 & 255);
						// 格式化MAC便于输出
						sprintf(mac_add, "%02X-%02X-%02X-%02X-%02X-%02X", recv->ah.source_mac_add[0],
							recv->ah.source_mac_add[1], recv->ah.source_mac_add[2], recv->ah.source_mac_add[3],
							recv->ah.source_mac_add[4], recv->ah.source_mac_add[5]);
						// 计算延迟时间并格式化
						delayTime = (double)pkt_header->ts.tv_usec / 1000;  // ts.tv_usec的单位是微秒，转成毫秒输出
						sprintf(delay, "%3.3fms", delayTime);               // 控制时间部分输出流显示浮点数的数字个数为3

						// 这里在原有程序基础上加入为ListView添加项的程序
						tmp = (recv->ah.source_ip_add >> 24 & 255);//下标
						if (mark[tmp] == 0)
						{
							AddListViewItems(hwndListView, ip_add, mac_add, delay);
							mark[tmp] = 1;
						}

						// 输出自己的IP
						if (tmp == myDevice.tmp)
						{
							EditBox = GetDlgItem(spara->myDlg, IDC_EDIT_MAC);
							SendMessage(EditBox, EM_SETREADONLY, 0, 0);
							SendMessage(EditBox, WM_SETTEXT, 0, (LPARAM)mac_add);
						}

						// 输出网关信息：我们主观认为网关末位是1或者是254
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

			// 收到发包线程的事件，则结束抓包，这个参数最好置零要不程序都不跑了……
			if (WaitForSingleObject(hEvent, 0) == WAIT_OBJECT_0)break;
		}

		Beep(880, 200);  // 响一下啦啦啦
		MessageBox(NULL, "嗅探结束！", "提示", MB_OK);
		ResetEvent(hEvent);
	}
    return 0;
}

BOOL AddListViewItems(HWND hwndListView, char *ip_add, char *mac_add, char *delay)
{
    LVITEM lvi;
    ZeroMemory(&lvi, sizeof(lvi));

    // 有效的项
    lvi.mask = LVIF_TEXT | LVIF_PARAM | LVIF_STATE;

    // 项的文本和长度
    lvi.pszText = ip_add;
    lvi.cchTextMax = lstrlen(lvi.pszText) + 1;

    // 插入列
    ListView_InsertItem(hwndListView, &lvi);
    ListView_SetItemText(hwndListView, 0, 1, mac_add);
    ListView_SetItemText(hwndListView, 0, 2, delay);

    return TRUE;
}