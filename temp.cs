using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace LastAuthentication.Service;

public static class SessionProcessLauncher
{
    // ==========================================
    // Константы
    // ==========================================

    private const uint MAXIMUM_ALLOWED = 0x02000000;

    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint NORMAL_PRIORITY_CLASS = 0x00000020;

    private const int STARTF_USESHOWWINDOW = 0x00000001;
    private const short SW_SHOWNORMAL = 1;

    private const int SecurityImpersonation = 2;
    private const int TokenPrimary = 1;

    private const int WTSActive = 0;

    private const uint WAIT_OBJECT_0 = 0x00000000;
    private const uint WAIT_TIMEOUT = 0x00000102;

    /// <summary>
    /// Сколько ждём, чтобы убедиться, что процесс
    /// не упал сразу после старта.
    /// </summary>
    private const uint AliveCheckTimeoutMs = 2000;


    // ==========================================
    // Логирование
    // ==========================================

    private static readonly string LogDirectory =
        Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData),
            "LastAuthentication");

    private static readonly string LogFile =
        Path.Combine(
            LogDirectory,
            "launcher.log");

    private static void Log(string message)
    {
        try
        {
            Directory.CreateDirectory(LogDirectory);

            string line =
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}";

            File.AppendAllText(
                LogFile,
                line + Environment.NewLine);
        }
        catch
        {
            // Диагностический лог не должен уронить службу.
        }
    }


    // ==========================================
    // Структуры
    // ==========================================

    [StructLayout(LayoutKind.Sequential)]
    private struct WTS_SESSION_INFO
    {
        public int SessionId;
        public IntPtr pWinStationName;
        public int State;
    }


    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFO
    {
        public uint cb;

        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;

        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;

        public uint dwXCountChars;
        public uint dwYCountChars;

        public uint dwFillAttribute;
        public uint dwFlags;

        public short wShowWindow;
        public short cbReserved2;

        public IntPtr lpReserved2;

        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }


    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;

        public uint dwProcessId;
        public uint dwThreadId;
    }


    // ==========================================
    // P/Invoke
    // ==========================================

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern int WTSEnumerateSessions(
        IntPtr hServer,
        int Reserved,
        int Version,
        out IntPtr ppSessionInfo,
        out int pCount);


    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(
        IntPtr pMemory);


    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(
        uint sessionId,
        out IntPtr phToken);


    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        IntPtr lpTokenAttributes,
        int impersonationLevel,
        int tokenType,
        out IntPtr phNewToken);


    [DllImport(
        "advapi32.dll",
        SetLastError = true,
        CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(
        IntPtr hToken,
        string? lpApplicationName,
        string? lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);


    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(
        out IntPtr lpEnvironment,
        IntPtr hToken,
        bool bInherit);


    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool DestroyEnvironmentBlock(
        IntPtr lpEnvironment);


    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(
        IntPtr hObject);


    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(
        IntPtr hHandle,
        uint dwMilliseconds);


    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(
        IntPtr hProcess,
        out uint lpExitCode);


    // ==========================================
    // Публичное API
    // ==========================================

    /// <summary>
    /// Запускает процесс в сессии конкретного
    /// пользователя, определяемого по SID.
    ///
    /// Это предпочтительный метод: на терминальных
    /// серверах и при нескольких сессиях он гарантирует,
    /// что UI увидит именно тот пользователь,
    /// который вошёл.
    /// </summary>
    public static bool LaunchForUser(
        string targetUserSid,
        string executablePath)
    {
        Log("========================================");
        Log("LaunchForUser STARTED");
        Log($"Target SID: {targetUserSid}");

        return LaunchInternal(
            executablePath,
            targetUserSid);
    }


    /// <summary>
    /// Запускает процесс в первой активной сессии.
    ///
    /// Оставлен для совместимости. По возможности
    /// используйте LaunchForUser.
    /// </summary>
    public static bool LaunchForActiveUser(
        string executablePath)
    {
        Log("========================================");
        Log("LaunchForActiveUser STARTED");

        return LaunchInternal(
            executablePath,
            null);
    }


    // ==========================================
    // Основная логика перебора сессий
    // ==========================================

    private static bool LaunchInternal(
        string executablePath,
        string? targetUserSid)
    {
        Log($"UI path: {executablePath}");
        Log($"Service process ID: {Environment.ProcessId}");
        Log($"Current user: {Environment.UserName}");
        Log($"Machine: {Environment.MachineName}");
        Log($"64-bit OS: {Environment.Is64BitOperatingSystem}");
        Log($"64-bit process: {Environment.Is64BitProcess}");

        try
        {
            if (!File.Exists(executablePath))
            {
                Log("ERROR: UI executable does not exist.");

                return false;
            }

            FileInfo fileInfo =
                new FileInfo(executablePath);

            Log($"UI file exists. Size={fileInfo.Length} bytes");
            Log($"UI LastWriteTime={fileInfo.LastWriteTime}");

            Log("Calling WTSEnumerateSessions...");

            IntPtr sessionInfoPtr = IntPtr.Zero;
            int count = 0;

            int result =
                WTSEnumerateSessions(
                    IntPtr.Zero,
                    0,
                    1,
                    out sessionInfoPtr,
                    out count);

            if (result == 0)
            {
                int error = Marshal.GetLastWin32Error();

                Log(
                    $"ERROR: WTSEnumerateSessions failed. " +
                    $"Win32={error}, " +
                    $"Message={new Win32Exception(error).Message}");

                return false;
            }

            Log($"WTSEnumerateSessions OK. Sessions={count}");

            try
            {
                int structSize =
                    Marshal.SizeOf<WTS_SESSION_INFO>();

                for (int i = 0; i < count; i++)
                {
                    IntPtr current =
                        IntPtr.Add(
                            sessionInfoPtr,
                            i * structSize);

                    WTS_SESSION_INFO session =
                        Marshal.PtrToStructure<WTS_SESSION_INFO>(
                            current);

                    Log(
                        $"Session found: " +
                        $"ID={session.SessionId}, " +
                        $"State={session.State}");

                    if (session.State != WTSActive)
                    {
                        continue;
                    }

                    /*
                     * Если задан целевой SID — проверяем,
                     * что это действительно сессия нужного
                     * пользователя.
                     */
                    if (targetUserSid != null)
                    {
                        string? sessionSid =
                            GetSessionUserSid(
                                (uint)session.SessionId);

                        Log(
                            $"Session {session.SessionId} " +
                            $"user SID: {sessionSid ?? "(unknown)"}");

                        if (!string.Equals(
                                sessionSid,
                                targetUserSid,
                                StringComparison.OrdinalIgnoreCase))
                        {
                            Log(
                                $"Session {session.SessionId} " +
                                $"does not match target SID. Skipping.");

                            continue;
                        }
                    }

                    Log($"TARGET SESSION: {session.SessionId}");

                    bool launched =
                        LaunchForSession(
                            (uint)session.SessionId,
                            executablePath);

                    if (launched)
                    {
                        Log(
                            $"SUCCESS: UI launched in session " +
                            $"{session.SessionId}");

                        return true;
                    }

                    Log(
                        $"LaunchForSession returned FALSE " +
                        $"for session {session.SessionId}");
                }
            }
            finally
            {
                WTSFreeMemory(sessionInfoPtr);
            }

            Log("ERROR: No suitable session could be used.");

            return false;
        }
        catch (Exception ex)
        {
            Log($"EXCEPTION in LaunchInternal: {ex}");

            return false;
        }
        finally
        {
            Log("Launch FINISHED");
            Log("========================================");
        }
    }


    /// <summary>
    /// Определяет SID пользователя, владеющего сессией.
    /// </summary>
    private static string? GetSessionUserSid(uint sessionId)
    {
        IntPtr token = IntPtr.Zero;

        try
        {
            if (!WTSQueryUserToken(sessionId, out token))
            {
                return null;
            }

            using WindowsIdentity identity =
                new WindowsIdentity(token);

            return identity.User?.Value;
        }
        catch
        {
            return null;
        }
        finally
        {
            if (token != IntPtr.Zero)
            {
                CloseHandle(token);
            }
        }
    }


    // ==========================================
    // Запуск в конкретной сессии
    // ==========================================

    /// <summary>
    /// Пытается запустить процесс в указанной сессии.
    ///
    /// Сначала используется наследование десктопа
    /// (lpDesktop = null) — это наиболее надёжный
    /// вариант, работающий и в консольных,
    /// и в RDP-сессиях.
    ///
    /// Если не получилось — повторная попытка
    /// с явным winsta0\default.
    /// </summary>
    private static bool LaunchForSession(
        uint sessionId,
        string executablePath)
    {
        Log($"--- LaunchForSession START --- Session={sessionId}");

        // Попытка 1: наследование десктопа.
        if (TryLaunch(
                sessionId,
                executablePath,
                null))
        {
            Log("--- LaunchForSession SUCCESS (inherited desktop) ---");

            return true;
        }

        Log("Retrying with explicit desktop winsta0\\default...");

        // Попытка 2: явное указание десктопа.
        if (TryLaunch(
                sessionId,
                executablePath,
                @"winsta0\default"))
        {
            Log("--- LaunchForSession SUCCESS (winsta0\\default) ---");

            return true;
        }

        Log("--- LaunchForSession FAILED (both attempts) ---");

        return false;
    }


    private static bool TryLaunch(
        uint sessionId,
        string executablePath,
        string? desktop)
    {
        IntPtr userToken = IntPtr.Zero;
        IntPtr primaryToken = IntPtr.Zero;
        IntPtr environment = IntPtr.Zero;

        PROCESS_INFORMATION processInfo =
            new PROCESS_INFORMATION();

        bool processCreated = false;

        try
        {
            // ------------------------------------------
            // WTSQueryUserToken
            // ------------------------------------------

            Log($"Calling WTSQueryUserToken({sessionId})...");

            if (!WTSQueryUserToken(sessionId, out userToken))
            {
                int error = Marshal.GetLastWin32Error();

                Log(
                    $"ERROR: WTSQueryUserToken FAILED. " +
                    $"Win32={error}, " +
                    $"Message={new Win32Exception(error).Message}");

                return false;
            }

            Log($"WTSQueryUserToken SUCCESS. Token={userToken}");


            // ------------------------------------------
            // DuplicateTokenEx
            // ------------------------------------------

            Log("Calling DuplicateTokenEx...");

            if (!DuplicateTokenEx(
                    userToken,
                    MAXIMUM_ALLOWED,
                    IntPtr.Zero,
                    SecurityImpersonation,
                    TokenPrimary,
                    out primaryToken))
            {
                int error = Marshal.GetLastWin32Error();

                Log(
                    $"ERROR: DuplicateTokenEx FAILED. " +
                    $"Win32={error}, " +
                    $"Message={new Win32Exception(error).Message}");

                return false;
            }

            Log($"DuplicateTokenEx SUCCESS. PrimaryToken={primaryToken}");


            // ------------------------------------------
            // CreateEnvironmentBlock
            // ------------------------------------------

            Log("Calling CreateEnvironmentBlock...");

            if (!CreateEnvironmentBlock(
                    out environment,
                    primaryToken,
                    false))
            {
                int error = Marshal.GetLastWin32Error();

                Log(
                    $"WARNING: CreateEnvironmentBlock FAILED. " +
                    $"Win32={error}, " +
                    $"Message={new Win32Exception(error).Message}");

                /*
                 * Не критично: продолжаем без
                 * пользовательского окружения.
                 */
                environment = IntPtr.Zero;
            }
            else
            {
                Log(
                    $"CreateEnvironmentBlock SUCCESS. " +
                    $"Environment={environment}");
            }


            // ------------------------------------------
            // STARTUPINFO
            // ------------------------------------------

            STARTUPINFO startupInfo = new STARTUPINFO();

            startupInfo.cb =
                (uint)Marshal.SizeOf<STARTUPINFO>();

            startupInfo.lpDesktop = desktop;

            startupInfo.dwFlags = STARTF_USESHOWWINDOW;

            startupInfo.wShowWindow = SW_SHOWNORMAL;

            Log(
                $"STARTUPINFO configured. " +
                $"Desktop={desktop ?? "(null, inherited)"}");


            // ------------------------------------------
            // CreateProcessAsUser
            // ------------------------------------------

            uint creationFlags =
                NORMAL_PRIORITY_CLASS;

            if (environment != IntPtr.Zero)
            {
                creationFlags |= CREATE_UNICODE_ENVIRONMENT;
            }

            string? workingDirectory =
                Path.GetDirectoryName(executablePath);

            Log("Calling CreateProcessAsUser...");
            Log($"ApplicationName={executablePath}");
            Log($"WorkingDirectory={workingDirectory}");
            Log($"CreationFlags={creationFlags}");

            processCreated =
                CreateProcessAsUser(
                    primaryToken,
                    executablePath,
                    null,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    creationFlags,
                    environment,
                    workingDirectory,
                    ref startupInfo,
                    out processInfo);

            if (!processCreated)
            {
                int error = Marshal.GetLastWin32Error();

                Log(
                    $"ERROR: CreateProcessAsUser FAILED. " +
                    $"Win32={error}, " +
                    $"Message={new Win32Exception(error).Message}");

                return false;
            }

            Log("CreateProcessAsUser SUCCESS!");
            Log($"PID={processInfo.dwProcessId}");
            Log($"ThreadID={processInfo.dwThreadId}");
            Log($"Session={sessionId}");


            // ------------------------------------------
            // Проверка: процесс выжил?
            // ------------------------------------------

            uint waitResult =
                WaitForSingleObject(
                    processInfo.hProcess,
                    AliveCheckTimeoutMs);

            if (waitResult == WAIT_TIMEOUT)
            {
                Log(
                    $"UI still running after " +
                    $"{AliveCheckTimeoutMs} ms — OK.");

                return true;
            }

            if (waitResult == WAIT_OBJECT_0)
            {
                if (GetExitCodeProcess(
                        processInfo.hProcess,
                        out uint exitCode))
                {
                    Log(
                        $"UI EXITED EARLY. " +
                        $"ExitCode={exitCode} " +
                        $"(0x{exitCode:X8}) " +
                        $"{DescribeExitCode(exitCode)}");
                }
                else
                {
                    int err = Marshal.GetLastWin32Error();

                    Log($"GetExitCodeProcess FAILED. Win32={err}");
                }

                return false;
            }

            int waitError = Marshal.GetLastWin32Error();

            Log(
                $"WaitForSingleObject returned {waitResult}, " +
                $"Win32={waitError}");

            return false;
        }
        catch (Exception ex)
        {
            Log($"EXCEPTION in TryLaunch: {ex}");

            return false;
        }
        finally
        {
            if (processCreated)
            {
                if (processInfo.hThread != IntPtr.Zero)
                {
                    CloseHandle(processInfo.hThread);
                }

                if (processInfo.hProcess != IntPtr.Zero)
                {
                    CloseHandle(processInfo.hProcess);
                }
            }

            if (environment != IntPtr.Zero)
            {
                DestroyEnvironmentBlock(environment);
            }

            if (primaryToken != IntPtr.Zero)
            {
                CloseHandle(primaryToken);
            }

            if (userToken != IntPtr.Zero)
            {
                CloseHandle(userToken);
            }
        }
    }


    /// <summary>
    /// Расшифровка типичных кодов выхода,
    /// чтобы не гадать по логу.
    /// </summary>
    private static string DescribeExitCode(uint exitCode)
    {
        return exitCode switch
        {
            0x00000000 => "— normal exit",
            0xC0000142 => "— STATUS_DLL_INIT_FAILED " +
                          "(нет доступа к window station/desktop)",
            0xC0000135 => "— STATUS_DLL_NOT_FOUND " +
                          "(отсутствует DLL)",
            0x80008096 => "— .NET host: runtimeconfig/deps не найден",
            0x80008083 => "— .NET host: несовместимая версия фреймворка",
            0x80008081 => "— .NET host: отсутствует требуемый runtime",
            150        => "— отсутствует требуемый .NET runtime",
            _          => string.Empty
        };
    }
}
