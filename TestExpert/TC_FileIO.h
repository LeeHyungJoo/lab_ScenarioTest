#pragma once

class TC_FileIO : public ITestCase
{
public:
	bool Run() override
	{
		_Scenario_1();
		_Scenario_2();
		_Scenario_3();
		_Scenario_4();
		_Scenario_5();

		return true;
	}

private:
	void _Scenario_1();
	void _Scenario_2();
	void _Scenario_3();
	void _Scenario_4();
	void _Scenario_5();
};
