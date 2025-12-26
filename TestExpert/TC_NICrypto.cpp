
#include "stdafx.h"
#include "TC_NICrypto.h"
#include "../Lib/NICrypto.h"

#pragma comment ( lib, "NICrypto_2.0_win64.lib")


bool TC_NICrypto::Run()
{
	NICryptoInitialize(1);

	return false;
}
