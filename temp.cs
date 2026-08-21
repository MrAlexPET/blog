Get-CimInstance Win32_Service -Filter "Name='LastAuthenticationService'" |
    Select-Object Name, StartName, State, PathName