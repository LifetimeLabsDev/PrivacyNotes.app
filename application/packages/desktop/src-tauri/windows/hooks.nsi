; NSIS installer hooks. Runs inside Tauri's generated installer.nsi via
; bundle.windows.nsis.installerHooks.
;
; WHY THIS FILE EXISTS
;
; Tauri's template turns bundle.fileAssociations into an APP_ASSOCIATE call,
; which writes Software\Classes\.<ext> default value = our file class. In the
; default currentUser install mode that lands in HKCU, and HKCU\Software\Classes
; outranks HKLM in the merged HKCR view - so on any machine without a per-user
; UserChoice for the extension (the normal case for .md), installing PrivacyNotes
; SILENTLY MADE IT THE DEFAULT MARKDOWN EDITOR. It also rewrote .txt's type
; description and icon. Taking the association from Obsidian, VS Code or Typora
; without asking would enrage exactly the users this feature is for, and the
; spec forbids it in as many words.
;
; NSIS_HOOK_POSTINSTALL is inserted AFTER the association block in the generated
; script (line ~733 vs ~663 in tauri-cli v2.11.4), so this hook can undo the
; default claim and leave the rest of the registration standing. That ordering is
; the load-bearing assumption; re-check it on a Tauri bump.
;
; WHAT WE KEEP
;
; Being IN the Open With list is the good half of a file association and we want
; it. So the hook writes its own ProgID plus OpenWithProgids, and the Capabilities
; and RegisteredApplications keys that Tauri writes for nobody - without those,
; Windows Settings cannot find the app by name and the ms-settings deep link in
; src/file_assoc.rs has nothing to land on.
;
; Our own ProgID, deliberately not Tauri's "Markdown document" class: that name
; comes from fileAssociations[].name, which is also the macOS CFBundleTypeName, so
; it is not ours to shape. A ProgID we create is decoupled from that and from
; Tauri's template naming.
;
; Windows will NOT let an installer or an app set the default itself - Microsoft
; blocked it in Windows 8 and since Windows 10 SHOpenWithDialog ignores its own
; registration flags. The user does it in Settings, which is what the in-app
; button opens.
;
; Spec: ops/docs/plans/markdown-folder.md (section 11), ops/docs/windows-release.md

; ${If} reaches the generated script only transitively, through MUI2.nsh. Include
; it directly rather than depending on that: LogicLib guards itself, so a second
; include is a no-op, and this file stops caring what MUI2 pulls in.
!include LogicLib.nsh

!macro NSIS_HOOK_POSTINSTALL
  ; ── 1. Undo Tauri's default claim, per extension ─────────────────────────
  ; APP_ASSOCIATE saved the previous default under "<FILECLASS>_backup" before
  ; overwriting it. Put it back, or delete the value outright when there was
  ; nothing there, which returns the machine to the state it was in.
  ; The backup value name must match fileAssociations[].name in tauri.conf.json;
  ; the two move together.
  !insertmacro PN_RESTORE_DEFAULT ".md"       "Markdown document"
  !insertmacro PN_RESTORE_DEFAULT ".markdown" "Markdown document"
  !insertmacro PN_RESTORE_DEFAULT ".mdown"    "Markdown document"
  !insertmacro PN_RESTORE_DEFAULT ".mkd"      "Markdown document"
  !insertmacro PN_RESTORE_DEFAULT ".txt"      "Plain text document"

  ; ── 2. Our own ProgIDs, one per file kind ────────────────────────────────
  ; TWO of them, and the second is not redundant. A ProgID's default value is the
  ; type name Explorer shows in its Type column, so pointing .txt at the Markdown
  ; ProgID would relabel every plain-text file on the machine as "Markdown
  ; document" the moment a user picked PrivacyNotes for .txt in Settings. The
  ; label follows the file kind, not the app.
  !insertmacro PN_PROGID "PrivacyNotes.Markdown" "Markdown document"
  !insertmacro PN_PROGID "PrivacyNotes.Text"     "Plain text document"

  ; ── 3. Offer, never take: appear in Open With for each extension ─────────
  !insertmacro PN_OPEN_WITH ".md"       "PrivacyNotes.Markdown"
  !insertmacro PN_OPEN_WITH ".markdown" "PrivacyNotes.Markdown"
  !insertmacro PN_OPEN_WITH ".mdown"    "PrivacyNotes.Markdown"
  !insertmacro PN_OPEN_WITH ".mkd"      "PrivacyNotes.Markdown"
  !insertmacro PN_OPEN_WITH ".txt"      "PrivacyNotes.Text"

  ; ── 4. Capabilities, so Settings can find us by name ────────────────────
  WriteRegStr SHCTX "Software\${PRODUCTNAME}\Capabilities" "ApplicationName" "${PRODUCTNAME}"
  WriteRegStr SHCTX "Software\${PRODUCTNAME}\Capabilities" "ApplicationDescription" "End-to-end encrypted notes, with a Markdown editor for your own files."
  WriteRegStr SHCTX "Software\${PRODUCTNAME}\Capabilities\FileAssociations" ".md" "PrivacyNotes.Markdown"
  WriteRegStr SHCTX "Software\${PRODUCTNAME}\Capabilities\FileAssociations" ".markdown" "PrivacyNotes.Markdown"
  WriteRegStr SHCTX "Software\${PRODUCTNAME}\Capabilities\FileAssociations" ".mdown" "PrivacyNotes.Markdown"
  WriteRegStr SHCTX "Software\${PRODUCTNAME}\Capabilities\FileAssociations" ".mkd" "PrivacyNotes.Markdown"
  ; .txt is registered as a capability so the user CAN choose it in Settings, and
  ; is deliberately absent from anything that would pre-select it. Claiming plain
  ; text by default would make us the editor for every README and log on the
  ; machine; the in-app button never touches it either. Its own ProgID, so
  ; choosing it does not relabel every text file as a Markdown document.
  WriteRegStr SHCTX "Software\${PRODUCTNAME}\Capabilities\FileAssociations" ".txt" "PrivacyNotes.Text"

  ; The named value here is what ms-settings:defaultapps?registeredAppUser= takes,
  ; so it must stay byte-identical to DEFAULT_APPS_URI in src/file_assoc.rs.
  WriteRegStr SHCTX "Software\RegisteredApplications" "${PRODUCTNAME}" "Software\${PRODUCTNAME}\Capabilities"

  ; Tell the shell the class table changed, or Explorer keeps showing the old
  ; Open With list until the next sign-in.
  !insertmacro UPDATEFILEASSOC
!macroend

; ALL of the uninstall cleanup happens here, in POSTUNINSTALL, and none of it in
; PREUNINSTALL. That is not arbitrary tidiness: Tauri inserts PREUNINSTALL at
; installer.nsi line ~779 and CheckIfAppIsRunning at ~782, and that macro can
; Abort the entire uninstall (the app is running, or the user backs out at its
; prompt). Cleanup in PREUNINSTALL therefore runs BEFORE the uninstall is
; committed, and an aborted uninstall would leave a fully installed, working app
; stripped of its ProgIDs, its Open With entries and its Settings registration -
; with no code path anywhere that ever puts them back. POSTUNINSTALL runs at ~887,
; after everything that can abort.
;
; It also has to run after Tauri's own APP_UNASSOCIATE block (~801), because it is
; cleaning up after that too:
;
; APP_UNASSOCIATE is unconditional:
;   ReadRegStr $R0 SHCTX "Software\Classes\.<ext>" "<FILECLASS>_backup"
;   WriteRegStr SHCTX "Software\Classes\.<ext>" "" "$R0"
; When the extension had NO default before we were installed, $R0 is empty and
; that writes an EMPTY ProgID as the extension's default. HKCU\Software\Classes
; shadows HKLM in the merged HKCR view, so an empty HKCU default for .txt can
; leave a machine with no working text-file association after uninstalling us -
; we would have broken Notepad on the way out.
;
; We cannot stop that macro from running, so we delete the empty value it leaves.
; Only ever an EMPTY value: a non-empty one is a real previous handler being
; correctly restored, and must be left exactly where it is.
; Uninstall order in the generated script: NSIS_HOOK_PREUNINSTALL (~line 779),
; APP_UNASSOCIATE (~801), NSIS_HOOK_POSTUNINSTALL (~887). Re-check on a Tauri bump.
!macro NSIS_HOOK_POSTUNINSTALL
  DeleteRegKey SHCTX "Software\Classes\PrivacyNotes.Markdown"
  DeleteRegKey SHCTX "Software\Classes\PrivacyNotes.Text"
  !insertmacro PN_OPEN_WITH_REMOVE ".md"       "PrivacyNotes.Markdown"
  !insertmacro PN_OPEN_WITH_REMOVE ".markdown" "PrivacyNotes.Markdown"
  !insertmacro PN_OPEN_WITH_REMOVE ".mdown"    "PrivacyNotes.Markdown"
  !insertmacro PN_OPEN_WITH_REMOVE ".mkd"      "PrivacyNotes.Markdown"
  !insertmacro PN_OPEN_WITH_REMOVE ".txt"      "PrivacyNotes.Text"
  DeleteRegValue SHCTX "Software\RegisteredApplications" "${PRODUCTNAME}"
  DeleteRegKey SHCTX "Software\${PRODUCTNAME}\Capabilities"
  ; Only removes the key when it has no subkeys or values left, so a future
  ; sibling setting under Software\PrivacyNotes survives an uninstall.
  DeleteRegKey /ifempty SHCTX "Software\${PRODUCTNAME}"

  !insertmacro PN_CLEAR_EMPTY_DEFAULT ".md"
  !insertmacro PN_CLEAR_EMPTY_DEFAULT ".markdown"
  !insertmacro PN_CLEAR_EMPTY_DEFAULT ".mdown"
  !insertmacro PN_CLEAR_EMPTY_DEFAULT ".mkd"
  !insertmacro PN_CLEAR_EMPTY_DEFAULT ".txt"
  !insertmacro UPDATEFILEASSOC
!macroend

; ── helpers ───────────────────────────────────────────────────────────────

; Put an extension's previous default handler back, undoing APP_ASSOCIATE.
;
; The `<FILECLASS>_backup` value is deliberately LEFT IN PLACE. Deleting it looks
; like tidying and is a bug: APP_UNASSOCIATE reads that exact value at uninstall
; and writes whatever it finds back as the extension's default, so a deleted
; backup means uninstalling writes an empty ProgID over a working association.
; Leaving it makes the two macros agree - we restore the original now, and the
; uninstaller restores the same value again, which is a no-op. It also survives an
; upgrade: APP_ASSOCIATE re-reads the (now original) default and re-records it.
; A stray registry value is a far cheaper outcome than a broken .txt handler.
!macro PN_RESTORE_DEFAULT EXT FILECLASS
  ClearErrors
  ReadRegStr $R0 SHCTX "Software\Classes\${EXT}" "${FILECLASS}_backup"
  ${If} $R0 == ""
    ; No previous handler recorded: the extension had no HKCU default before we
    ; installed, so removing ours is the restore.
    DeleteRegValue SHCTX "Software\Classes\${EXT}" ""
  ${Else}
    WriteRegStr SHCTX "Software\Classes\${EXT}" "" "$R0"
  ${EndIf}
!macroend

; Delete an extension's default value only when it is empty. See the comment on
; NSIS_HOOK_POSTUNINSTALL for why an empty one can exist and why it is harmful.
!macro PN_CLEAR_EMPTY_DEFAULT EXT
  ClearErrors
  ReadRegStr $R0 SHCTX "Software\Classes\${EXT}" ""
  ${If} $R0 == ""
    DeleteRegValue SHCTX "Software\Classes\${EXT}" ""
    ; And the now-orphaned key, but only if nothing else lives under it.
    DeleteRegKey /ifempty SHCTX "Software\Classes\${EXT}"
  ${EndIf}
!macroend

; One ProgID: the type name Explorer shows, our icon, and the open command.
!macro PN_PROGID PROGID TYPENAME
  WriteRegStr SHCTX "Software\Classes\${PROGID}" "" "${TYPENAME}"
  WriteRegStr SHCTX "Software\Classes\${PROGID}\DefaultIcon" "" "$INSTDIR\${MAINBINARYNAME}.exe,0"
  WriteRegStr SHCTX "Software\Classes\${PROGID}\shell\open" "" "Open with ${PRODUCTNAME}"
  WriteRegStr SHCTX "Software\Classes\${PROGID}\shell\open\command" "" '"$INSTDIR\${MAINBINARYNAME}.exe" "%1"'
!macroend

; List PrivacyNotes among an extension's Open With candidates without owning it.
; An empty-string value is the documented shape for an OpenWithProgids entry.
!macro PN_OPEN_WITH EXT PROGID
  WriteRegStr SHCTX "Software\Classes\${EXT}\OpenWithProgids" "${PROGID}" ""
!macroend

!macro PN_OPEN_WITH_REMOVE EXT PROGID
  DeleteRegValue SHCTX "Software\Classes\${EXT}\OpenWithProgids" "${PROGID}"
!macroend
