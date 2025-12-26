#pragma once

#include "stdafx.h"
#include <vector>
#include <memory>
#include <iostream>

class Tester
{
public:
	void Add(unique_ptr<ITestCase> test)
	{
		tests.push_back(move(test));
	}

	void RunAll() const
	{
		for (const auto& t : tests)
		{
			bool ok = t->Run();
			wcout << (ok ? "[PASS] " : "[FAIL] ")
				<< t->Run() << '\n';
		}
	}

private:
	vector<unique_ptr<ITestCase>> tests;
};
