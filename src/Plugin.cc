
#include "Plugin.h"

namespace plugin { namespace Zeek_ZsonHttp { Plugin plugin; } }

using namespace plugin::Zeek_ZsonHttp;

plugin::Configuration Plugin::Configure()
	{
        AddComponent(new ::logging::Component("ZsonHttp", ::logging::writer::ZsonHttp::Instantiate));

	plugin::Configuration config;
	config.name = "Zeek::ZsonHttp";
	config.description = "Plugin to POST Zeek logs via HTTP";
	config.version.major = version_major;
	config.version.minor = version_minor;
	return config;
	}
