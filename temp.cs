Get-Process LastAuthentication.UI -ErrorAction SilentlyContinue |
    Select-Object Id, SessionId, StartTime, Path