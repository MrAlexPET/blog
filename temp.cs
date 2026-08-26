#define MyAppName "LastAuthentication"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Alex"
#define MyServiceName "LastAuthenticationService"

[Setup]
AppId={{A6F2E3D1-6B54-4B2F-9D11-123456789ABC}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}

DefaultDirName={autopf}\LastAuthentication

DisableProgramGroupPage=yes

OutputDir=Output
OutputBaseFilename=LastAuthenticationSetup

Compression=lzma2
SolidCompression=yes

PrivilegesRequired=admin

ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

UninstallDisplayName=LastAuthentication
UninstallDisplayIcon={app}\LastAuthentication.Service.exe


[Files]

Source: "publish\*"; \
DestDir: "{app}"; \
Flags: recursesubdirs createallsubdirs ignoreversion


[Run]

; Если служба уже существует — сначала остановим
Filename: "{sys}\sc.exe"; \
Parameters: "stop {#MyServiceName}"; \
Flags: runhidden waituntilterminated skipifdoesntexist

; Создаём службу
Filename: "{sys}\sc.exe"; \
Parameters: "create {#MyServiceName} binPath= ""{app}\LastAuthentication.Service.exe"" start= auto obj= LocalSystem"; \
Flags: runhidden waituntilterminated

; Запускаем службу
Filename: "{sys}\sc.exe"; \
Parameters: "start {#MyServiceName}"; \
Flags: runhidden waituntilterminated


[UninstallRun]

; Останавливаем службу
Filename: "{sys}\sc.exe"; \
Parameters: "stop {#MyServiceName}"; \
Flags: runhidden waituntilterminated

; Удаляем службу
Filename: "{sys}\sc.exe"; \
Parameters: "delete {#MyServiceName}"; \
Flags: runhidden waituntilterminated


[UninstallDelete]

Type: filesandordirs; Name: "{app}"