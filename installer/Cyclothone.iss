
[Setup]
AppId={{B8C7A8E5-4D0E-4E9B-A5B4-2D1F8D7C6E21}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\Cyclothone
DefaultGroupName=Cyclothone
OutputDir=output
OutputBaseFilename=Cyclothone-Setup
Compression=lzma
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64
ArchitecturesAllowed=x64
PrivilegesRequired=admin
UninstallDisplayIcon={app}\{#AppExeName}

[Files]
Source: "..\target\x86_64-pc-windows-msvc\release\cyclothone-agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\x86_64-pc-windows-msvc\release\cyclothone-desktop.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\agent\install-service.ps1"; DestDir: "{app}\agent"; Flags: ignoreversion

[Registry]
Root: HKLM; Subkey: "Software\Classes\cyclothone"; ValueType: string; ValueName: ""; ValueData: "URL:Cyclothone Enrollment"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\cyclothone"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Classes\cyclothone\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExeName}"" ""%1"""

[Run]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\agent\install-service.ps1"""; Flags: runhidden waituntilterminated
Filename: "{app}\{#AppExeName}"; Description: "Launch Cyclothone"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Stop-Service -Name 'CyclothoneAgent' -Force -ErrorAction SilentlyContinue; sc.exe delete CyclothoneAgent | Out-Null"""; Flags: runhidden waituntilterminated
