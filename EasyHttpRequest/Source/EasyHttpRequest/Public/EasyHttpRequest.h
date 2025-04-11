// Ryckbosch Arthur 2024, Inc. All Rights Reserved.

#pragma once

#include "Modules/ModuleManager.h"

class FEasyHttpRequestModule : public IModuleInterface
{
public:

	/** IModuleInterface implementation */
	virtual void StartupModule() override;
	virtual void ShutdownModule() override;
};
