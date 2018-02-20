; ==============================================================================
Local $version = "0.98"
Local $expHash = "0xBC08BE1D87BF135A2B8F139A4FCD93F0AE027A87AE0A8374DD1716A18E1E2DEC"
; ==============================================================================

#include <Crypt.au3>
#include <InetConstants.au3>

Local $title = "Npcap " & $version & " Setup"
Local $localFile = "npcap.exe"
Local $nb = InetGet("https://nmap.org/npcap/dist/npcap-" & $version & ".exe", $localFile, $INET_FORCERELOAD, $INET_DOWNLOADWAIT)
If ($nb <= 0) Then
  Exit 1
EndIf

_Crypt_Startup()
Local $hash = _Crypt_HashFile($localFile, $CALG_SHA_256)

If (String($hash) <> $expHash) Then
  Exit 2
EndIf

Run($localFile)

WinWait($title, "I &Agree")
SendKeepActive($title)
Send("!a")

WinWaitActive($title, "Installation Options")
If Not ControlCommand($title, "Installation Options", "[CLASS:Button; TEXT:Install Npcap in WinPcap API-compatible Mode]", "IsChecked") Then
  ControlCommand($title, "Installation Options", "[CLASS:Button; TEXT:Install Npcap in WinPcap API-compatible Mode]", "Check")
EndIf
Send("!i")

WinWaitActive($title, "Installation Complete")
Send("!n")

WinWaitActive($title, "Finished")
Send("{ENTER}")