; === Morse-Kirby Provenance Engine – System Setup v1.0.0 ===
#define AppName        "Morse-Kirby Provenance Engine"
#define AppVersion     "1.0.0"
#define InstallDir     "{autopf}\MKPE"
#define SourceDir      "C:\MKPE_Release\v1.0.0"
#define OutputDir      "C:\MKPE_Distribution"

[Setup]
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=Morse-Kirby Development Team
AppPublisherURL=https://morsekirby.com
AppSupportURL=https://morsekirby.com/support
AppUpdatesURL=https://morsekirby.com/updates
DefaultDirName={#InstallDir}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir={#OutputDir}
OutputBaseFilename=MKPE_v1.0.0_SystemSetup
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=admin
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64
VersionInfoVersion={#AppVersion}
VersionInfoCompany=Morse-Kirby Development Team
VersionInfoDescription=Cryptographic Provenance Engine
VersionInfoCopyright=Copyright (C) 2025
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "addtopath"; Description: "Add MKPE to system PATH"; GroupDescription: "System Integration:"; Flags: unchecked
Name: "registerservice"; Description: "Install MKPE Integrity Service (continuous monitoring)"; GroupDescription: "System Integration:"
Name: "startupicon"; Description: "Start MKPE UI with Windows"; GroupDescription: "User Experience:"

[Files]
; Core executables
Source: "{#SourceDir}\cli\mkpe.exe"; DestDir: "{app}\bin"; Flags: ignoreversion
Source: "{#SourceDir}\core\morse_kirby_core.lib"; DestDir: "{app}\lib"; Flags: ignoreversion; Check: FileExists('{#SourceDir}\core\morse_kirby_core.lib')

; Configuration files
Source: "{#SourceDir}\mkpe_config.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\MKPE_v1.0.0_manifest.json"; DestDir: "{app}"; Flags: ignoreversion

; Documentation
Source: "{#SourceDir}\docs\*"; DestDir: "{app}\docs"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\*.md"; DestDir: "{app}"; Flags: ignoreversion

; Proof artifacts
Source: "{#SourceDir}\*.mkpe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\*.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\*.json"; DestDir: "{app}"; Flags: ignoreversion

; Service files
Source: "{#SourceDir}\service\*"; DestDir: "{app}\service"; Flags: ignoreversion recursesubdirs createallsubdirs

; Validation and examples
Source: "{#SourceDir}\validation\*"; DestDir: "{app}\validation"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\examples\*"; DestDir: "{app}\examples"; Flags: ignoreversion recursesubdirs createallsubdirs

; Layer specs
Source: "{#SourceDir}\attestation\*"; DestDir: "{app}\attestation"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\stego\*"; DestDir: "{app}\stego"; Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
Name: "{commonappdata}\MKPE\logs"; Permissions: users-full
Name: "{commonappdata}\MKPE\audit"; Permissions: users-full
Name: "{app}\proofs"

[Icons]
Name: "{group}\MKPE Command Prompt"; Filename: "{cmd}"; Parameters: "/K cd /D ""{app}\bin"""; Comment: "MKPE command-line interface"
Name: "{group}\MKPE Documentation"; Filename: "{app}\docs"; Comment: "MKPE documentation folder"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"

[Registry]
Root: HKLM; Subkey: "Software\MKPE"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\MKPE"; ValueType: string; ValueName: "Version"; ValueData: "{#AppVersion}"
Root: HKLM; Subkey: "Software\MKPE"; ValueType: string; ValueName: "ManifestID"; ValueData: "6260a764-7901-4997-9a85-898d728e760d"
Root: HKLM; Subkey: "Software\MKPE"; ValueType: string; ValueName: "RootHash"; ValueData: "9b5041f701ba5279"

; File association for .mkpe files
Root: HKCR; Subkey: ".mkpe"; ValueType: string; ValueName: ""; ValueData: "MKPEFile"; Flags: uninsdeletevalue
Root: HKCR; Subkey: "MKPEFile"; ValueType: string; ValueName: ""; ValueData: "MKPE Provenance Bundle"; Flags: uninsdeletekey
Root: HKCR; Subkey: "MKPEFile\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\bin\mkpe.exe,0"
Root: HKCR; Subkey: "MKPEFile\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\bin\mkpe.exe"" verify ""%1"""
Root: HKCR; Subkey: "MKPEFile\shell\inspect\command"; ValueType: string; ValueName: ""; ValueData: """{app}\bin\mkpe.exe"" inspect ""%1"""

[Run]
; Register service if task selected
Filename: "powershell.exe"; \
  Parameters: "-ExecutionPolicy Bypass -File ""{app}\service\Register-MKPEService.ps1"""; \
  Flags: runhidden waituntilterminated; \
  Tasks: registerservice; \
  StatusMsg: "Registering MKPE Integrity Service..."

; Verify installation
Filename: "{app}\bin\mkpe.exe"; Parameters: "version"; Flags: runhidden waituntilterminated postinstall skipifsilent; Description: "Verify MKPE installation"

[UninstallRun]
; Stop and remove service
Filename: "powershell.exe"; \
  Parameters: "-ExecutionPolicy Bypass -Command ""Stop-Service MKPEIntegrityService -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2; sc.exe delete MKPEIntegrityService | Out-Null"""; \
  Flags: runhidden waituntilterminated

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
var
  TaskSelected: Boolean;
begin
  if CurStep = ssPostInstall then
  begin
    TaskSelected := WizardIsTaskSelected('addtopath');
    if TaskSelected then
    begin
      // Add to system PATH
      Exec('cmd.exe', '/C setx PATH "%PATH%;' + ExpandConstant('{app}') + '\bin" /M', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    end;

    MsgBox('{#AppName} {#AppVersion} installed successfully.'#13#10#13#10 +
           'Installation path: ' + ExpandConstant('{app}') + #13#10 +
           'CLI tool: mkpe.exe'#13#10#13#10 +
           'The MKPE system is now ready for use.',
           mbInformation, MB_OK);
  end;
end;
```



