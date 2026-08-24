Get-WinEvent -LogName Application -MaxEvents 30 |
    Where-Object {
        $_.ProviderName -like "*LastAuthentication*"
    } |
    Select-Object TimeCreated, ProviderName, Message |
    Format-List