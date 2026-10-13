// SPDX-License-Identifier: GPL-3.0-or-later
#include <obs-module.h>
#include <QtCore/qglobal.h>

OBS_DECLARE_MODULE()
OBS_MODULE_USE_DEFAULT_LOCALE("obs-air", "en-US")

void register_air_source();

MODULE_EXPORT const char *obs_module_description()
{
    return "AirPlay screen mirroring and audio for OBS Studio";
}

MODULE_EXPORT const char *obs_module_author()
{
    return "haliluya.net";
}

bool obs_module_load()
{
    register_air_source();
    blog(LOG_INFO, "[OBS-Air] %s loaded (OBS SDK 32, Qt %s, C++17)", OBS_AIR_VERSION, qVersion());
    return true;
}
