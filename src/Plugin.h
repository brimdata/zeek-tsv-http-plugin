
#ifndef BRO_PLUGIN_ZEEK_TSVHTTP
#define BRO_PLUGIN_ZEEK_TSVHTTP

#include "TsvHttp.h"
#include <plugin/Plugin.h>

namespace plugin {
namespace Zeek_TsvHttp {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}

#endif
