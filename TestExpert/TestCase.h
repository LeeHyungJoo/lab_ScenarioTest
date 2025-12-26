#pragma once


class ITestCase
{
public:
	virtual ~ITestCase() = default;
	virtual bool Run() = 0;
};
