;NSIS installer for DOME Local signer

;--------------------------------
;Include Modern UI

  !include "MUI2.nsh"

;--------------------------------
;General

  ;Name and file
  Name "DOME ELSigner"
  OutFile "ELSignerInstaller.exe"
  Unicode True
  
  ;We do not need admin access as we install in the user profile dir
  RequestExecutionLevel user

  ;Default installation folder
  InstallDir "$PROFILE\.DOMEELSigner"
    
  SetCompress off

;--------------------------------
;Interface Settings

  !define MUI_ABORTWARNING
  !define MUI_HEADERIMAGE
  !define MUI_HEADERIMAGE_BITMAP "domeicon.bmp"

;--------------------------------
;Pages

  !insertmacro MUI_PAGE_WELCOME
  !insertmacro MUI_PAGE_LICENSE "LICENSE"
  !insertmacro MUI_PAGE_COMPONENTS
  !insertmacro MUI_PAGE_DIRECTORY
  !insertmacro MUI_PAGE_INSTFILES
  
  !insertmacro MUI_UNPAGE_WELCOME
  !insertmacro MUI_UNPAGE_CONFIRM
  !insertmacro MUI_UNPAGE_INSTFILES
  
;--------------------------------
;Languages
 
  !insertmacro MUI_LANGUAGE "English"

;--------------------------------
;Installer Sections

Section "Local signer" SecDummy

  SetOutPath "$INSTDIR"
  
  File elsigner.exe
    
  ;Create uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  
  CreateShortcut "$DESKTOP\DOME Signer.lnk" "$INSTDIR\elsigner.exe"

SectionEnd

;--------------------------------
;Descriptions

  ;Language strings
  LangString DESC_SecDummy ${LANG_ENGLISH} "The program to sign LEARCredentials with eIDAS certificates."

  ;Assign language strings to sections
  !insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecDummy} $(DESC_SecDummy)
  !insertmacro MUI_FUNCTION_DESCRIPTION_END

;--------------------------------
;Uninstaller Section

Section "Uninstall"

  Delete "$INSTDIR\elsigner.exe"
  Delete "$INSTDIR\Uninstall.exe"
  Delete "$DESKTOP\DOME Signer.lnk"

  RMDir "$INSTDIR"

SectionEnd