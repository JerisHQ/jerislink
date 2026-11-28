// JerisLink Windows host, H3: the connection settings window.
#pragma once

namespace jlh::config {
struct Location;
}

namespace jlh::settingsui {

// The window, until it closes (the caller is elevated). 0, or 70 when
// the window could not be created.
int runConnectionSettings(const jlh::config::Location& loc);

}  // namespace jlh::settingsui
