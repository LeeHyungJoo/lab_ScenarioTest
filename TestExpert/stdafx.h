#pragma once

#define _AFXDLL
#include <io.h>
#include <iostream>

using namespace std;

#define BUFFER_SIZE 1024
#define PATH_DISKLOCK (_T("D:\\TestRead\\disklock.ini"))

#include "../Lib/NICrypto.h"
#pragma comment ( lib, "NICrypto_2.0_win64.lib")
#include "TestCase.h"