# Cyclothone Windows installer
#define AppName "Cyclothone"
#define AppVersion "0.1.0"
#define AppPublisher "Cyclothone"
#define AppExe "cyclothone-desktop.exe"

[Setup]
AppId={{C2B9F0B5-1E5D-4F9B-9E2B-6A7C9B7E9D10}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\Cyclothone
DefaultGroupName=Cyclothone
OutputDir=output
OutputBaseFilename=Cyclothone-Setup
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#AppExe}

[Files]
Source: "..\target\x86_64-pc-windows-msvc\release\cyclothone-agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\x86_64-pc-windows-msvc\release\cyclothone-desktop.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "register-agent-service.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\agent\install-service.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Cyclothone"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\Cyclothone"; Filename: "{app}\{#AppExe}"

[Run]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\register-agent-service.ps1"" -InstallRoot ""{app}"""; StatusMsg: "Registering Cyclothone Agent service…"; Flags: runhidden waituntilterminated
Filename: "{app}\{#AppExe}"; Description: "Open Cyclothone"; Flags: postinstall nowait skipifsilent

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""$s=Get-Service -Name 'CyclothoneAgent' -ErrorAction SilentlyContinue; if($s){ if($s.Status -ne 'Stopped'){Stop-Service -Name 'CyclothoneAgent' -Force -ErrorAction SilentlyContinue}; sc.exe delete CyclothoneAgent | Out-Null }"""; RunOnceId: "RemoveCyclothoneAgent"

[Code]
function InitializeSetup(): Boolean;
begin
  Result := IsAdminInstallMode;
end;
