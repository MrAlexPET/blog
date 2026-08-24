TimeCreated      : 24.08.2026 11:23:02
Id               : 0
LevelDisplayName : Ошибка
Message          : Category: LastAuthentication.Service.AuthenticationService
                   EventId: 0

                   Failed to launch LastAuthentication.UI.

                   Exception:
                   System.EntryPointNotFoundException: Unable to find an entry point named 'WTSGetActiveConsoleSessionI
                   d' in DLL 'wtsapi32.dll'.
                      at LastAuthentication.Service.SessionProcessLauncher.WTSGetActiveConsoleSessionId()
                      at LastAuthentication.Service.SessionProcessLauncher.LaunchForActiveUser(String executablePath) i
                   n D:\Login_program\LastAuthentication\LastAuthentication.Service\SessionProcessLauncher.cs:line 123
                      at LastAuthentication.Service.AuthenticationService.LaunchUserInterface() in D:\Login_program\Las
                   tAuthentication\LastAuthentication.Service\AuthenticationService.cs:line 190
