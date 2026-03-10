; Mesh Infinity — NSIS Installer Script
; Requires NSIS 3.x with MUI2 plugin
;
; Usage:
;   makensis /DAPP_NAME=meshinfinity /DAPP_VERSION=0.2.0 /DPROFILE=release installer.nsi
;
; The bundle directory must be at:
;   ..\..\build\intermediates\windows\bundle\${PROFILE}\
; The output DMG goes to:
;   ..\..\build\output\windows\${PROFILE}\

!include "MUI2.nsh"

; ── Compile-time parameters (override via /D on command line) ──────────────────
!ifndef APP_NAME
  !define APP_NAME "meshinfinity"
!endif
!ifndef APP_VERSION
  !define APP_VERSION "0.0.0"
!endif
!ifndef PROFILE
  !define PROFILE "release"
!endif

; ── Installer metadata ────────────────────────────────────────────────────────
Name            "Mesh Infinity ${APP_VERSION}"
OutFile         "..\..\build\output\windows\${PROFILE}\${APP_NAME}-${APP_VERSION}-${PROFILE}-setup.exe"
InstallDir      "$PROGRAMFILES64\Mesh Infinity"
InstallDirRegKey HKLM "Software\MeshInfinity" "InstallDir"
RequestExecutionLevel admin
Unicode True

; ── MUI pages ─────────────────────────────────────────────────────────────────
!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; ── Install section ───────────────────────────────────────────────────────────
Section "MainSection" SEC01
  SetOutPath "$INSTDIR"
  File /r "..\..\build\intermediates\windows\bundle\${PROFILE}\*.*"

  ; Write uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  ; Add/Remove Programs registry entry
  WriteRegStr HKLM \
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\MeshInfinity" \
    "DisplayName" "Mesh Infinity"
  WriteRegStr HKLM \
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\MeshInfinity" \
    "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKLM \
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\MeshInfinity" \
    "Publisher" "Onii Media Works"
  WriteRegStr HKLM \
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\MeshInfinity" \
    "UninstallString" "$\"$INSTDIR\Uninstall.exe$\""
  WriteRegStr HKLM \
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\MeshInfinity" \
    "InstallLocation" "$INSTDIR"
  WriteRegDWORD HKLM \
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\MeshInfinity" \
    "NoModify" 1
  WriteRegDWORD HKLM \
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\MeshInfinity" \
    "NoRepair" 1

  ; Install path for future reference
  WriteRegStr HKLM "Software\MeshInfinity" "InstallDir" "$INSTDIR"

  ; Start Menu shortcut
  CreateDirectory "$SMPROGRAMS\Mesh Infinity"
  CreateShortcut "$SMPROGRAMS\Mesh Infinity\Mesh Infinity.lnk" \
    "$INSTDIR\mesh_infinity_frontend.exe"
  CreateShortcut "$SMPROGRAMS\Mesh Infinity\Uninstall.lnk" \
    "$INSTDIR\Uninstall.exe"

  ; Desktop shortcut
  CreateShortcut "$DESKTOP\Mesh Infinity.lnk" \
    "$INSTDIR\mesh_infinity_frontend.exe"
SectionEnd

; ── Uninstall section ─────────────────────────────────────────────────────────
Section "Uninstall"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir /r "$INSTDIR"

  Delete "$SMPROGRAMS\Mesh Infinity\Mesh Infinity.lnk"
  Delete "$SMPROGRAMS\Mesh Infinity\Uninstall.lnk"
  RMDir  "$SMPROGRAMS\Mesh Infinity"
  Delete "$DESKTOP\Mesh Infinity.lnk"

  DeleteRegKey HKLM \
    "Software\Microsoft\Windows\CurrentVersion\Uninstall\MeshInfinity"
  DeleteRegKey HKLM "Software\MeshInfinity"
SectionEnd
