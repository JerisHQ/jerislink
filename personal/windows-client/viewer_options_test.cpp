// Unit tests for viewer_options.hpp (launch config resolution). Console app; exit 0 = pass.
#include "viewer_options.hpp"

#include <cstdio>

static int gFailures = 0;
static int gChecks = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        ++gChecks;                                                         \
        if (!(cond)) {                                                     \
            ++gFailures;                                                   \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
        }                                                                  \
    } while (0)

using namespace jl;
using Args = std::vector<std::string>;

static SavedSettings morrisSaved() {
    SavedSettings s;
    s.hostIp = "100.64.0.25";
    s.codec = "hevc";
    s.bitrateMbps = 18;
    return s;
}

int main() {
    const std::optional<std::string> tailnet = std::string("100.64.0.16");
    const std::optional<std::string> noTailnet;

    // No arguments, saved settings: connects to the saved host, bind auto-detected.
    {
        auto r = resolveLaunch({}, morrisSaved(), "", tailnet);
        CHECK(r.status == LaunchStatus::Ok);
        CHECK(r.options.sourceIp == "100.64.0.25");
        CHECK(r.hostSource == "saved");
        CHECK(r.options.bindIp == "100.64.0.16");
        CHECK(r.bindSource == "auto");
        CHECK(r.options.codec == "hevc");
        CHECK(r.options.bitrateMbps == 18);
        CHECK(!r.openSettings);
    }
    // First run: nothing saved, no env -> settings dialog.
    {
        auto r = resolveLaunch({}, SavedSettings{}, "", tailnet);
        CHECK(r.status == LaunchStatus::NeedsSetup);
        CHECK(r.options.codec == "h264");
        CHECK(r.options.bitrateMbps == 25);
    }
    // The old full command line still works and wins over saved settings.
    {
        Args a{"--bind-ip", "100.64.0.16", "--source-ip", "100.64.0.25",
               "--codec", "hevc", "--bitrate-mbps", "18"};
        SavedSettings s;
        s.hostIp = "100.64.0.99";
        s.bindIp = "100.64.0.98";
        s.codec = "h264";
        s.bitrateMbps = 40;
        auto r = resolveLaunch(a, s, "100.64.0.97", noTailnet);
        CHECK(r.status == LaunchStatus::Ok);
        CHECK(r.options.sourceIp == "100.64.0.25" && r.hostSource == "cli");
        CHECK(r.options.bindIp == "100.64.0.16" && r.bindSource == "cli");
        CHECK(r.options.codec == "hevc");
        CHECK(r.options.bitrateMbps == 18);
    }
    // Saved bind IP overrides auto-detect.
    {
        auto s = morrisSaved();
        s.bindIp = "100.64.0.42";
        auto r = resolveLaunch({}, s, "", tailnet);
        CHECK(r.options.bindIp == "100.64.0.42" && r.bindSource == "saved");
    }
    // Saved host wins over JERISLINK_SOURCE_IP; env is used when nothing is saved.
    {
        auto r = resolveLaunch({}, morrisSaved(), "100.64.0.7", tailnet);
        CHECK(r.options.sourceIp == "100.64.0.25" && r.hostSource == "saved");
        auto e = resolveLaunch({}, SavedSettings{}, "100.64.0.7", tailnet);
        CHECK(e.status == LaunchStatus::Ok);
        CHECK(e.options.sourceIp == "100.64.0.7" && e.hostSource == "env");
    }
    // No tailnet address and none saved.
    {
        auto r = resolveLaunch({}, morrisSaved(), "", noTailnet);
        CHECK(r.status == LaunchStatus::NoTailnet);
        CHECK(r.bindSource == "none");
    }
    // A corrupt saved host is treated as unset.
    {
        auto s = morrisSaved();
        s.hostIp = "100.64.0";
        auto r = resolveLaunch({}, s, "", tailnet);
        CHECK(r.status == LaunchStatus::NeedsSetup);
    }
    // --settings and --print-config are flags, not connection settings.
    {
        auto r = resolveLaunch({"--settings", "--print-config", "C:\\t\\out.txt"},
                               morrisSaved(), "", tailnet);
        CHECK(r.status == LaunchStatus::Ok);
        CHECK(r.openSettings);
        CHECK(r.printConfigPath == "C:\\t\\out.txt");
    }
    // Invalid arguments are still rejected.
    {
        CHECK(resolveLaunch({"--codec", "vp9"}, morrisSaved(), "", tailnet).status == LaunchStatus::InvalidArgs);
        CHECK(resolveLaunch({"--bitrate-mbps", "2"}, morrisSaved(), "", tailnet).status == LaunchStatus::InvalidArgs);
        CHECK(resolveLaunch({"--port", "abc"}, morrisSaved(), "", tailnet).status == LaunchStatus::InvalidArgs);
        CHECK(resolveLaunch({"--source-ip"}, morrisSaved(), "", tailnet).status == LaunchStatus::InvalidArgs);
        CHECK(resolveLaunch({"--bogus", "1"}, morrisSaved(), "", tailnet).status == LaunchStatus::InvalidArgs);
    }
    // IPv4 validation.
    {
        CHECK(isIPv4("100.64.0.25"));
        CHECK(isIPv4("0.0.0.0"));
        CHECK(!isIPv4(""));
        CHECK(!isIPv4("100.64.0"));
        CHECK(!isIPv4("100.64.0.256"));
        CHECK(!isIPv4("100.64.0.25."));
        CHECK(!isIPv4("100.64..25"));
        CHECK(!isIPv4("01.2.3.4"));
        CHECK(!isIPv4("1.2.3.4.5"));
        CHECK(!isIPv4("host.local"));
        CHECK(!isIPv4("1234.1.1.1"));
    }
    // describeLaunch output used by --print-config.
    {
        auto d = describeLaunch(resolveLaunch({}, morrisSaved(), "", tailnet));
        CHECK(d.find("status=ok\n") != std::string::npos);
        CHECK(d.find("host=100.64.0.25\n") != std::string::npos);
        CHECK(d.find("host_source=saved\n") != std::string::npos);
    }

    std::printf("viewer_options_test: %d checks, %d failures\n", gChecks, gFailures);
    return gFailures == 0 ? 0 : 1;
}
