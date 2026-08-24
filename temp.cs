Get-WinEvent -LogName Application -MaxEvents 50 |
    Where-Object {
        $_.Message -like "*UI*" -or
        $_.Message -like "*LastAuthentication*"
    } |
    Select-Object TimeCreated, Message |
    Format-List
