Get-CimInstance Win32_Process |
    Where-Object {
        $_.Name -eq "LastAuthentication.UI.exe"
    } |
    Select-Object ProcessId, SessionId, ExecutablePath, CommandLine