Get-WinEvent -LogName Application -MaxEvents 50 |
    Where-Object {
        $_.Message -like "*CreateProcessAsUser*" -or
        $_.Message -like "*WTSQueryUserToken*" -or
        $_.Message -like "*DuplicateTokenEx*" -or
        $_.Message -like "*CreateEnvironmentBlock*" -or
        $_.Message -like "*PROCESS CREATED*"
    } |
    Select-Object TimeCreated, Message |
    Format-List