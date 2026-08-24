[2026-08-24 14:15:59.312] ========================================
[2026-08-24 14:15:59.344] LaunchForActiveUser STARTED
[2026-08-24 14:15:59.344] UI path: D:\Login_program\LastAuthentication\LastAuthentication.Service\bin\Release\net8.0-windows\win-x64\publish\LastAuthentication.UI.exe
[2026-08-24 14:15:59.345] Service process ID: 21240
[2026-08-24 14:15:59.351] Current user: EXO-PC3$
[2026-08-24 14:15:59.352] Machine: EXO-PC3
[2026-08-24 14:15:59.353] 64-bit OS: True
[2026-08-24 14:15:59.353] 64-bit process: True
[2026-08-24 14:15:59.354] UI file exists. Size=151552 bytes
[2026-08-24 14:15:59.363] UI LastWriteTime=24.08.2026 10:27:27
[2026-08-24 14:15:59.364] Calling WTSEnumerateSessions...
[2026-08-24 14:15:59.367] WTSEnumerateSessions OK. Sessions=4
[2026-08-24 14:15:59.369] Session found: ID=0, State=4
[2026-08-24 14:15:59.370] Session found: ID=8, State=1
[2026-08-24 14:15:59.373] Session found: ID=11, State=0
[2026-08-24 14:15:59.374] ACTIVE SESSION FOUND: 11
[2026-08-24 14:15:59.376] --- LaunchForSession START --- Session=11
[2026-08-24 14:15:59.377] Calling WTSQueryUserToken(11)...
[2026-08-24 14:15:59.379] WTSQueryUserToken SUCCESS. Token=1448
[2026-08-24 14:15:59.379] Calling DuplicateTokenEx...
[2026-08-24 14:15:59.381] DuplicateTokenEx SUCCESS. PrimaryToken=1468
[2026-08-24 14:15:59.382] Calling CreateEnvironmentBlock...
[2026-08-24 14:15:59.387] CreateEnvironmentBlock SUCCESS. Environment=2763813332704
[2026-08-24 14:15:59.387] STARTUPINFO configured. Desktop=winsta0\default
[2026-08-24 14:15:59.388] Calling CreateProcessAsUser...
[2026-08-24 14:15:59.389] ApplicationName=D:\Login_program\LastAuthentication\LastAuthentication.Service\bin\Release\net8.0-windows\win-x64\publish\LastAuthentication.UI.exe
[2026-08-24 14:15:59.390] WorkingDirectory=D:\Login_program\LastAuthentication\LastAuthentication.Service\bin\Release\net8.0-windows\win-x64\publish
[2026-08-24 14:15:59.391] CreationFlags=1040
[2026-08-24 14:15:59.431] CreateProcessAsUser SUCCESS!
[2026-08-24 14:15:59.432] PID=15240
[2026-08-24 14:15:59.433] ThreadID=20712
[2026-08-24 14:15:59.434] Session=11
[2026-08-24 14:15:59.435] Process found immediately. PID=15240, Name=LastAuthentication.UI
[2026-08-24 14:15:59.951] Process no longer exists after 500ms.
[2026-08-24 14:15:59.952] --- LaunchForSession SUCCESS ---
[2026-08-24 14:15:59.952] SUCCESS: UI launched in session 11
[2026-08-24 14:15:59.953] LaunchForActiveUser FINISHED
[2026-08-24 14:15:59.954] ========================================
