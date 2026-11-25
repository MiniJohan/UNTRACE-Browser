; UNTRACE installer hooks for Tauri's NSIS template (M9).
;
; The uninstaller's "Delete the application data" checkbox removes Tauri's own folders
; ($LOCALAPPDATA\<bundle id>). UNTRACE keeps its data in %LOCALAPPDATA%\UNTRACE (settings,
; block lists, the engine's profiles, the activity log, crash reports), so the same checkbox
; removes that folder too. Never during an update (/UPDATE), which keeps everything.
!macro NSIS_HOOK_POSTUNINSTALL
  ${If} $DeleteAppDataCheckboxState = 1
  ${AndIf} $UpdateMode <> 1
    SetShellVarContext current
    RmDir /r "$LOCALAPPDATA\UNTRACE"
  ${EndIf}
!macroend
