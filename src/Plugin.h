
#ifndef BRO_PLUGIN_ZEEK_ZSONHTTP
#define BRO_PLUGIN_ZEEK_ZSONHTTP

#include "ZsonHttp.h"
#include <plugin/Plugin.h>

namespace plugin {
namespace Zeek_ZsonHttp {

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
