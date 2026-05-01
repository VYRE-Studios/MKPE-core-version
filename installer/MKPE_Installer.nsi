; MKPE v1.0.0 NSIS Installer Script
; Morse-Kirby Provenance Engine System Installer

!define PRODUCT_NAME "Morse-Kirby Provenance Engine"
!define PRODUCT_VERSION "1.0.0"
!define PRODUCT_PUBLISHER "Morse-Kirby Development"
!define INSTALL_DIR "$PROGRAMFILES\MKPE"

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "C:\MKPE_Distribution\MKPE_v1.0.0_SystemSetup.exe"
InstallDir "${INSTALL_DIR}"
RequestExecutionLevel admin

; Pages
Page directory
Page instfiles

Section "MainSection" SEC01
  SetOutPath "$INSTDIR"
  
  ; Copy all files from release
  File /r "C:\MKPE_Release\v1.0.0\*.*"
  
  ; Create directories
  CreateDirectory "$INSTDIR\bin"
  CreateDirectory "$INSTDIR\lib"
  CreateDirectory "$INSTDIR\service"
  CreateDirectory "$INSTDIR\ui"
  CreateDirectory "$APPDATA\..\Common\MKPE\logs"
  CreateDirectory "$APPDATA\..\Common\MKPE\audit"
  
  ; Move binaries to proper locations
  Rename "$INSTDIR\cli\mkpe.exe" "$INSTDIR\bin\mkpe.exe"
  Rename "$INSTDIR\service\mkpe_service.exe" "$INSTDIR\service\mkpe_service.exe"
  Rename "$INSTDIR\ui\mkpe_ui.exe" "$INSTDIR\ui\mkpe_ui.exe"
  
  ; Registry keys
  WriteRegStr HKLM "Software\MKPE" "InstallPath" "$INSTDIR"
  WriteRegStr HKLM "Software\MKPE" "Version" "${PRODUCT_VERSION}"
  WriteRegStr HKLM "Software\MKPE" "ManifestID" "6260a764-7901-4997-9a85-898d728e760d"
  WriteRegStr HKLM "Software\MKPE" "RootHash" "9b5041f701ba5279"
  
  ; .mkpe file association
  WriteRegStr HKCR ".mkpe" "" "MKPEFile"
  WriteRegStr HKCR "MKPEFile" "" "MKPE Provenance Bundle"
  WriteRegStr HKCR "MKPEFile\shell\verify\command" "" '"$INSTDIR\bin\mkpe.exe" verify "%1"'
  WriteRegStr HKCR "MKPEFile\shell\inspect\command" "" '"$INSTDIR\bin\mkpe.exe" inspect "%1"'
  
  ; Add to PATH (manual via powershell)
  nsExec::ExecToLog 'setx PATH "%PATH%;$INSTDIR\bin" /M'
  
  ; Register service
  nsExec::ExecToLog 'powershell -ExecutionPolicy Bypass -File "$INSTDIR\service\Register-MKPEService.ps1"'
  
  ; Create uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  
  ; Add to Add/Remove Programs
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MKPE" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MKPE" "UninstallString" "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MKPE" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MKPE" "Publisher" "${PRODUCT_PUBLISHER}"
  
  MessageBox MB_OK "MKPE v${PRODUCT_VERSION} installed successfully!$\n$\nCLI tool: mkpe.exe$\nService: $INSTDIR\service\mkpe_service.exe$\nUI: $INSTDIR\ui\mkpe_ui.exe"
  
SectionEnd

Section "Uninstall"
  ; Stop and remove service
  nsExec::ExecToLog 'sc stop MKPEIntegrityService'
  nsExec::ExecToLog 'sc delete MKPEIntegrityService'
  
  ; Remove files
  RMDir /r "$INSTDIR"
  
  ; Remove from PATH would require manual cleanup or registry edit
  
  ; Remove registry keys
  DeleteRegKey HKLM "Software\MKPE"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\MKPE"
  DeleteRegKey HKCR ".mkpe"
  DeleteRegKey HKCR "MKPEFile"
  
  ; Remove data folders (optional - ask user?)
  ; RMDir /r "$COMMONAPPDATA\MKPE"
  
  MessageBox MB_OK "MKPE has been uninstalled."
SectionEnd

