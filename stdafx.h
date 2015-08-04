// stdafx.h : 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 特定于项目的包含文件
//

#pragma once

#define _CRT_SECURE_NO_WARNINGS

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             //  从 Windows 头文件中排除极少使用的信息
// Windows 头文件: 
#include <windows.h>
#include <windowsx.h>

// C 运行时头文件
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>


// TODO:  在此处引用程序需要的其他头文件
#include <stdio.h>
#include <iostream>
#include <WinSock2.h>
#include <cstring>
#include "pcap.h"

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"wpcap.lib")
#include <commctrl.h>  //Listview

#pragma pack(1)  //按一个字节内存对齐

using namespace std;
