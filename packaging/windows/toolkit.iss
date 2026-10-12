#define AppVersion "2.0.0"
#ifndef BundleDir
  #define BundleDir "..\..\dist\CybersecurityFundamentalsToolkit"
#endif
[Setup]
AppId={{921B70E4-D638-45E8-9D71-CCF702AD58C7}
AppName=Cybersecurity Fundamentals Toolkit
AppVersion={#AppVersion}
AppPublisher=KreesM7
AppPublisherURL=https://github.com/KreesM7/cybersecurity-fundamentals-toolkit
DefaultDirName={localappdata}\Programs\CybersecurityFundamentalsToolkit
DefaultGroupName=Cybersecurity Fundamentals Toolkit
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\..\dist\installers
OutputBaseFilename=Toolkit-{#AppVersion}-Windows-x64-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\..\frontend\resources\icons\toolkit.ico
LicenseFile=..\..\COPYING
UninstallDisplayIcon={app}\CybersecurityFundamentalsToolkit.exe
[Files]
Source: "{#BundleDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
[Icons]
Name: "{group}\Cybersecurity Fundamentals Toolkit"; Filename: "{app}\CybersecurityFundamentalsToolkit.exe"
[Run]
Filename: "{app}\CybersecurityFundamentalsToolkit.exe"; Description: "Launch Toolkit"; Flags: nowait postinstall skipifsilent
; User profiles and independently installed tools are deliberately not removed.
