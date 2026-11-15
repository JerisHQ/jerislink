// Unit tests for viewer_options.hpp (launch config resolution). Console app; exit 0 = pass.
#include "viewer_options.hpp"
#include "bind_choices.hpp"

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

static SavedSettings typicalSaved() {
    SavedSettings s;
    s.hostIp = "192.0.2.25";
    s.codec = "hevc";
    s.bitrateMbps = 18;
    return s;
}

int main() {
    const std::optional<std::string> tailnet = std::string("198.51.100.16");
    const std::optional<std::string> noTailnet;

    // No arguments, saved settings: connects to the saved host, bind auto-detected.
    {
        auto r = resolveLaunch({}, typicalSaved(), "", tailnet);
        CHECK(r.status == LaunchStatus::Ok);
        CHECK(r.options.sourceIp == "192.0.2.25");
        CHECK(r.hostSource == "saved");
        CHECK(r.options.bindIp == "198.51.100.16");
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
        Args a{"--bind-ip", "198.51.100.16", "--source-ip", "192.0.2.25",
               "--codec", "hevc", "--bitrate-mbps", "18"};
        SavedSettings s;
        s.hostIp = "192.0.2.99";
        s.bindIp = "192.0.2.98";
        s.codec = "h264";
        s.bitrateMbps = 40;
        auto r = resolveLaunch(a, s, "192.0.2.97", noTailnet);
        CHECK(r.status == LaunchStatus::Ok);
        CHECK(r.options.sourceIp == "192.0.2.25" && r.hostSource == "cli");
        CHECK(r.options.bindIp == "198.51.100.16" && r.bindSource == "cli");
        CHECK(r.options.codec == "hevc");
        CHECK(r.options.bitrateMbps == 18);
    }
    // Saved bind IP overrides auto-detect.
    {
        auto s = typicalSaved();
        s.bindIp = "192.0.2.42";
        auto r = resolveLaunch({}, s, "", tailnet);
        CHECK(r.options.bindIp == "192.0.2.42" && r.bindSource == "saved");
    }
    // Saved host wins over JERISLINK_SOURCE_IP; env is used when nothing is saved.
    {
        auto r = resolveLaunch({}, typicalSaved(), "192.0.2.7", tailnet);
        CHECK(r.options.sourceIp == "192.0.2.25" && r.hostSource == "saved");
        auto e = resolveLaunch({}, SavedSettings{}, "192.0.2.7", tailnet);
        CHECK(e.status == LaunchStatus::Ok);
        CHECK(e.options.sourceIp == "192.0.2.7" && e.hostSource == "env");
    }
    // No tailnet address and none saved.
    {
        auto r = resolveLaunch({}, typicalSaved(), "", noTailnet);
        CHECK(r.status == LaunchStatus::NoTailnet);
        CHECK(r.bindSource == "none");
    }
    // A corrupt saved host is treated as unset.
    {
        auto s = typicalSaved();
        s.hostIp = "100.64.0";
        auto r = resolveLaunch({}, s, "", tailnet);
        CHECK(r.status == LaunchStatus::NeedsSetup);
    }
    // --settings and --print-config are flags, not connection settings.
    {
        auto r = resolveLaunch({"--settings", "--print-config", "C:\\t\\out.txt"},
                               typicalSaved(), "", tailnet);
        CHECK(r.status == LaunchStatus::Ok);
        CHECK(r.openSettings);
        CHECK(r.printConfigPath == "C:\\t\\out.txt");
    }
    // Invalid arguments are still rejected.
    {
        CHECK(resolveLaunch({"--codec", "vp9"}, typicalSaved(), "", tailnet).status == LaunchStatus::InvalidArgs);
        CHECK(resolveLaunch({"--bitrate-mbps", "2"}, typicalSaved(), "", tailnet).status == LaunchStatus::InvalidArgs);
        CHECK(resolveLaunch({"--nack", "maybe"}, typicalSaved(), "", tailnet).status == LaunchStatus::InvalidArgs);
        CHECK(resolveLaunch({}, typicalSaved(), "", tailnet).options.nack == "on");
        CHECK(resolveLaunch({"--nack", "off"}, typicalSaved(), "", tailnet).options.nack == "off");
        CHECK(resolveLaunch({"--abr", "maybe"}, typicalSaved(), "", tailnet).status == LaunchStatus::InvalidArgs);
        CHECK(resolveLaunch({}, typicalSaved(), "", tailnet).options.abr == "on");
        CHECK(resolveLaunch({"--abr", "off"}, typicalSaved(), "", tailnet).options.abr == "off");
        CHECK(resolveLaunch({"--audio", "loud"}, typicalSaved(), "", tailnet).status == LaunchStatus::InvalidArgs);
        CHECK(resolveLaunch({}, typicalSaved(), "", tailnet).options.audio == "on");
        CHECK(resolveLaunch({"--audio", "off"}, typicalSaved(), "", tailnet).options.audio == "off");
        CHECK(resolveLaunch({"--port", "abc"}, typicalSaved(), "", tailnet).status == LaunchStatus::InvalidArgs);
        CHECK(resolveLaunch({"--source-ip"}, typicalSaved(), "", tailnet).status == LaunchStatus::InvalidArgs);
        CHECK(resolveLaunch({"--bogus", "1"}, typicalSaved(), "", tailnet).status == LaunchStatus::InvalidArgs);
    }
    // --present-mode: waitable is the default, waitable1 and nowait still parse.
    {
        CHECK(resolveLaunch({}, typicalSaved(), "", tailnet).options.presentMode == "waitable");
        CHECK(resolveLaunch({"--present-mode", "nowait"}, typicalSaved(), "", tailnet).options.presentMode == "nowait");
        CHECK(resolveLaunch({"--present-mode", "waitable1"}, typicalSaved(), "", tailnet).options.presentMode == "waitable1");
        CHECK(resolveLaunch({"--present-mode", "vsync"}, typicalSaved(), "", tailnet).status == LaunchStatus::InvalidArgs);
    }
    // IPv4 validation.
    {
        CHECK(isIPv4("192.0.2.25"));
        CHECK(isIPv4("0.0.0.0"));
        CHECK(!isIPv4(""));
        CHECK(!isIPv4("100.64.0"));
        CHECK(!isIPv4("192.0.2.256"));
        CHECK(!isIPv4("192.0.2.25."));
        CHECK(!isIPv4("100.64..25"));
        CHECK(!isIPv4("01.2.3.4"));
        CHECK(!isIPv4("1.2.3.4.5"));
        CHECK(!isIPv4("host.local"));
        CHECK(!isIPv4("1234.1.1.1"));
    }
    // describeLaunch output used by --print-config.
    {
        auto d = describeLaunch(resolveLaunch({}, typicalSaved(), "", tailnet));
        CHECK(d.find("status=ok\n") != std::string::npos);
        CHECK(d.find("host=192.0.2.25\n") != std::string::npos);
        CHECK(d.find("host_source=saved\n") != std::string::npos);
    }

    // Debug mode (JERISLINK_DEBUG): off unless exactly "1".
    {
        CHECK(!debugModeEnabled(""));
        CHECK(debugModeEnabled("1"));
        CHECK(!debugModeEnabled("0"));
        CHECK(!debugModeEnabled("true"));
        CHECK(!debugModeEnabled(" 1"));
        CHECK(!debugModeEnabled("1 "));
    }

    // "This PC's address": Auto matches the Mac address; manual choices.
    {
        const std::string t = "100.64.0.25";     // this PC on the tailnet
        const std::string macT = "100.64.0.10";  // Mac on the tailnet
        const std::string macC = "127.0.0.1";    // Mac through the Tailcat bridge
        CHECK(isTailnetIPv4("100.64.0.1") && isTailnetIPv4("100.127.255.254"));
        CHECK(!isTailnetIPv4("100.128.0.1") && !isTailnetIPv4("100.63.255.255"));
        CHECK(isTailcatIPv4("127.0.0.1") && !isTailcatIPv4("128.0.0.1"));

        // Auto rule.
        CHECK(autoBindFor(macT, {t, true}).ip == t);
        CHECK(autoBindFor(macT, {t, true}).reason == "auto-tailnet");
        CHECK(autoBindFor(macC, {t, true}).ip == "127.0.0.1");
        CHECK(autoBindFor(macC, {t, true}).reason == "auto-tailcat");
        CHECK(autoBindFor(macC, {t, false}).ip == t);  // bridge missing: old rule
        CHECK(autoBindFor(macC, {t, false}).reason == "fallback");
        CHECK(autoBindFor(macT, {std::nullopt, true}).reason == "none");
        CHECK(autoBindFor("192.0.2.25", {t, true}).ip == t);
        CHECK(autoBindFor("192.0.2.25", {t, true}).reason == "fallback");
        CHECK(autoBindFor("", {}).ip.empty());

        // Launch: empty BindIp = Auto, saved IP = manual, --bind-ip wins.
        SavedSettings s = typicalSaved();
        s.hostIp = macC;
        s.bindIp = "";
        auto r = resolveLaunch({}, s, "", BindDetection{t, true});
        CHECK(r.status == LaunchStatus::Ok && r.options.bindIp == "127.0.0.1");
        CHECK(r.bindSource == "auto" && r.bindReason == "auto-tailcat");
        s.hostIp = macT;
        r = resolveLaunch({}, s, "", BindDetection{t, true});
        CHECK(r.options.bindIp == t && r.bindReason == "auto-tailnet");
        r = resolveLaunch({}, s, "", BindDetection{std::nullopt, true});
        CHECK(r.status == LaunchStatus::NoTailnet && r.bindReason == "none");
        s.bindIp = "127.0.0.1";
        r = resolveLaunch({}, s, "", BindDetection{t, true});
        CHECK(r.options.bindIp == "127.0.0.1" && r.bindSource == "saved" && r.bindReason == "manual");
        r = resolveLaunch({"--bind-ip", "192.0.2.9"}, s, "", BindDetection{t, true});
        CHECK(r.options.bindIp == "192.0.2.9" && r.bindReason == "cli");
        CHECK(describeLaunch(r).find("bind_reason=cli\n") != std::string::npos);

        // Dialog choices.
        auto none = bindChoices({}, "");
        CHECK(none.size() == 1 && none[0].kind == BindKind::Auto);
        CHECK(initialBindChoice(none, "") == 0);
        CHECK(bindValueToSave(none, 0, "") == "");
        CHECK(bindValueToSave(none, -1, "192.0.2.7") == "192.0.2.7");

        auto both = bindChoices({t, true}, "");
        CHECK(both.size() == 3);
        CHECK(both[1].kind == BindKind::Tailnet && both[1].ip == t);
        CHECK(both[2].kind == BindKind::Tailcat && both[2].ip == "127.0.0.1");
        CHECK(initialBindChoice(both, "") == 0);
        CHECK(bindValueToSave(both, 0, t) == "");  // back to Auto
        CHECK(bindValueToSave(both, 1, "") == t);
        CHECK(bindValueToSave(both, 2, "") == "127.0.0.1");
        CHECK(bindValueToSave(both, 7, "x") == "x");
        CHECK(initialBindChoice(bindChoices({t, true}, t), t) == 1);
        CHECK(initialBindChoice(bindChoices({t, true}, "127.0.0.1"), "127.0.0.1") == 2);

        // A saved manual IP not detected now stays selectable and is kept.
        auto kept = bindChoices({t, false}, "192.0.2.7");
        CHECK(kept.size() == 3 && kept[2].kind == BindKind::Saved);
        const int k = initialBindChoice(kept, "192.0.2.7");
        CHECK(k == 2 && bindValueToSave(kept, k, "192.0.2.7") == "192.0.2.7");
        CHECK(bindChoices({t, false}, "junk").size() == 2);
    }

    // Launch screen: shown unless the host came on the command line.
    {
        auto saved = resolveLaunch({}, typicalSaved(), "", tailnet);
        CHECK(showLaunchScreen(saved, false));
        auto none = resolveLaunch({}, SavedSettings{}, "", tailnet);
        CHECK(none.status == LaunchStatus::NeedsSetup && showLaunchScreen(none, false));
        auto env = resolveLaunch({}, SavedSettings{}, "192.0.2.40", tailnet);
        CHECK(env.hostSource == "env" && showLaunchScreen(env, false));
        auto cli = resolveLaunch({"--source-ip", "192.0.2.30"}, typicalSaved(), "", tailnet);
        CHECK(cli.hostSource == "cli" && !showLaunchScreen(cli, false));
        CHECK(showLaunchScreen(cli, true));  // Shift held
        auto cliSettings = resolveLaunch({"--source-ip", "192.0.2.30", "--settings"},
                                         typicalSaved(), "", tailnet);
        CHECK(showLaunchScreen(cliSettings, false));
        auto bad = resolveLaunch({"--codec", "vp9"}, typicalSaved(), "", tailnet);
        CHECK(!showLaunchScreen(bad, true));
        auto print = resolveLaunch({"--print-config", "x.txt"}, typicalSaved(), "", tailnet);
        CHECK(!showLaunchScreen(print, true));

        // The address typed on the launch screen (saved) wins over --source-ip.
        const Args args{"--source-ip", "192.0.2.30", "--settings", "--audio", "off"};
        const Args after = argsAfterLaunchScreen(args);
        CHECK((after == Args{"--audio", "off"}));
        auto typed = resolveLaunch(after, typicalSaved(), "", tailnet);
        CHECK(typed.options.sourceIp == "192.0.2.25" && typed.hostSource == "saved");
        CHECK(typed.options.audio == "off");

        // Back to the launch screen after a session: same arguments, --settings once.
        CHECK((argsForRelaunch({}) == Args{"--settings"}));
        CHECK((argsForRelaunch({"--audio", "off", "--settings"}) == Args{"--audio", "off", "--settings"}));
        auto relaunch = resolveLaunch(argsForRelaunch({"--source-ip", "192.0.2.30"}),
                                      typicalSaved(), "", tailnet);
        CHECK(relaunch.openSettings && showLaunchScreen(relaunch, false));
    }

    std::printf("viewer_options_test: %d checks, %d failures\n", gChecks, gFailures);
    return gFailures == 0 ? 0 : 1;
}
