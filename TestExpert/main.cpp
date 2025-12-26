#include "stdafx.h"
#include "Tester.h"
#include "TC_FileIO.h"

void main()
{
	Tester mainTester = Tester();
	mainTester.Add(make_unique<TC_FileIO>());
	mainTester.RunAll();

	return;
}