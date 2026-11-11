#define MyAppName "Jerislink"
#define MyAppVersion "0.0.9.5"
#define MyAppPublisher "Jeris"
#define MyAppExeName "Jerislink.exe"

[Setup]
AppId={{94D797F8-5A5A-4CF4-86F8-3B0760D4A0B4}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\Jeris\Jerislink
DefaultGroupName=Jerislink
DisableProgramGroupPage=yes
OutputDir=dist
OutputBaseFilename=Jerislink-{#MyAppVersion}-windows-x64-setup
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
UninstallDisplayIcon={app}\{#MyAppExeName}
WizardStyle=modern

[Files]
Source: "build\Release\Jerislink.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "README-Windows.txt"; DestDir: "{app}"; DestName: "README.txt"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\Jerislink"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\Jerislink"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Jerislink"; Flags: nowait postinstall skipifsilent
