Get-WinEvent -LogName Application -MaxEvents 50 |
    Where-Object {
        $_.ProviderName -eq "LastAuthentication.Service" -or
        $_.Message -like "*LastAuthentication.Service*"
    } |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-List