Get-WinEvent -LogName Application -MaxEvents 100 |
    Where-Object {
        $_.ProviderName -eq "LastAuthentication Service"
    } |
    Select-Object TimeCreated, Message |
    Format-List