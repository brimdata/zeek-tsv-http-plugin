
#include "Plugin.h"

namespace plugin { namespace Zeek_TsvHttp { Plugin plugin; } }

using namespace plugin::Zeek_TsvHttp;

plugin::Configuration Plugin::Configure()
	{
        AddComponent(new ::logging::Component("TsvHttp", ::logging::writer::TsvHttp::Instantiate));

	plugin::Configuration config;
	config.name = "Zeek::TsvHttp";
	config.description = "Plugin to POST Zeek logs via HTTP";
	config.version.major = version_major;
	config.version.minor = version_minor;
	return config;
	}
