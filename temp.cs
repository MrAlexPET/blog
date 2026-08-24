using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace LastAuthentication.Service;

public static class SessionProcessLauncher
{
    private const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
    private const uint TOKEN_DUPLICATE = 0x0002;
    private const uint TOKEN_QUERY = 0x0008;

    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint CREATE_NEW_CONSOLE = 0x00000010;

    private const int STARTF_USESHOWWINDOW = 0x00000001;
    private const short SW_SHOWNORMAL = 1;

    private const int SecurityImpersonation = 2;
    private const int TokenPrimary = 1;

    private const int WTSActive = 0;

    private static readonly string LogDirectory =
        Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData),
            "LastAuthentication");

    private static readonly string LogFile =
        Path.Combine(
            LogDirectory,
            "launcher.log");


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


    [DllImport(
        "wtsapi32.dll",
        SetLastError = true)]
    private static extern int WTSEnumerateSessions(
        IntPtr hServer,
        int Reserved,
        int Version,
        out IntPtr ppSessionInfo,
        out int pCount);


    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(
        IntPtr pMemory);


    [DllImport(
        "wtsapi32.dll",
        SetLastError = true)]
    private static extern bool WTSQueryUserToken(
        uint sessionId,
        out IntPtr phToken);


    [DllImport(
        "advapi32.dll",
        SetLastError = true)]
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


    [DllImport(
        "userenv.dll",
        SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(
        out IntPtr lpEnvironment,
        IntPtr hToken,
        bool bInherit);


    [DllImport(
        "userenv.dll",
        SetLastError = true)]
    private static extern bool DestroyEnvironmentBlock(
        IntPtr lpEnvironment);


    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    private static extern bool CloseHandle(
        IntPtr hObject);


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
            // Диагностический лог не должен
            // уронить службу.
        }
    }


    public static bool LaunchForActiveUser(
        string executablePath)
    {
        Log("========================================");
        Log("LaunchForActiveUser STARTED");
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

            IntPtr sessionInfoPtr =
                IntPtr.Zero;

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
                int error =
                    Marshal.GetLastWin32Error();

                Log(
                    $"ERROR: WTSEnumerateSessions failed. " +
                    $"Win32={error}, " +
                    $"Message={new Win32Exception(error).Message}");

                return false;
            }

            Log(
                $"WTSEnumerateSessions OK. " +
                $"Sessions={count}");

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

                    Log(
                        $"ACTIVE SESSION FOUND: " +
                        $"{session.SessionId}");

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
                WTSFreeMemory(
                    sessionInfoPtr);
            }

            Log(
                "ERROR: No active session could be used.");

            return false;
        }
        catch (Exception ex)
        {
            Log(
                $"EXCEPTION in LaunchForActiveUser: " +
                $"{ex}");

            return false;
        }
        finally
        {
            Log("LaunchForActiveUser FINISHED");
            Log("========================================");
        }
    }


    private static bool LaunchForSession(
        uint sessionId,
        string executablePath)
    {
        IntPtr userToken =
            IntPtr.Zero;

        IntPtr primaryToken =
            IntPtr.Zero;

        IntPtr environment =
            IntPtr.Zero;

        try
        {
            Log(
                $"--- LaunchForSession START --- " +
                $"Session={sessionId}");

            // ==========================================
            // WTSQueryUserToken
            // ==========================================

            Log(
                $"Calling WTSQueryUserToken({sessionId})...");

            if (!WTSQueryUserToken(
                    sessionId,
                    out userToken))
            {
                int error =
                    Marshal.GetLastWin32Error();

                Log(
                    $"ERROR: WTSQueryUserToken FAILED. " +
                    $"Win32={error}, " +
                    $"Message={new Win32Exception(error).Message}");

                return false;
            }

            Log(
                $"WTSQueryUserToken SUCCESS. " +
                $"Token={userToken}");


            // ==========================================
            // DuplicateTokenEx
            // ==========================================

            Log(
                "Calling DuplicateTokenEx...");

            if (!DuplicateTokenEx(
                    userToken,
                    TOKEN_ASSIGN_PRIMARY |
                    TOKEN_DUPLICATE |
                    TOKEN_QUERY,
                    IntPtr.Zero,
                    SecurityImpersonation,
                    TokenPrimary,
                    out primaryToken))
            {
                int error =
                    Marshal.GetLastWin32Error();

                Log(
                    $"ERROR: DuplicateTokenEx FAILED. " +
                    $"Win32={error}, " +
                    $"Message={new Win32Exception(error).Message}");

                return false;
            }

            Log(
                $"DuplicateTokenEx SUCCESS. " +
                $"PrimaryToken={primaryToken}");


            // ==========================================
            // CreateEnvironmentBlock
            // ==========================================

            Log(
                "Calling CreateEnvironmentBlock...");

            if (!CreateEnvironmentBlock(
                    out environment,
                    primaryToken,
                    false))
            {
                int error =
                    Marshal.GetLastWin32Error();

                Log(
                    $"ERROR: CreateEnvironmentBlock FAILED. " +
                    $"Win32={error}, " +
                    $"Message={new Win32Exception(error).Message}");

                return false;
            }

            Log(
                $"CreateEnvironmentBlock SUCCESS. " +
                $"Environment={environment}");


            // ==========================================
            // STARTUPINFO
            // ==========================================

            var startupInfo =
                new STARTUPINFO();

            startupInfo.cb =
                (uint)Marshal.SizeOf<STARTUPINFO>();

            startupInfo.lpDesktop =
                @"winsta0\default";

            startupInfo.dwFlags =
                STARTF_USESHOWWINDOW;

            startupInfo.wShowWindow =
                SW_SHOWNORMAL;

            Log(
                $"STARTUPINFO configured. " +
                $"Desktop={startupInfo.lpDesktop}");


            // ==========================================
            // CREATE PROCESS
            // ==========================================

            var processInfo =
                new PROCESS_INFORMATION();

            uint creationFlags =
                CREATE_UNICODE_ENVIRONMENT |
                CREATE_NEW_CONSOLE;

            string? workingDirectory =
                Path.GetDirectoryName(
                    executablePath);

            Log(
                "Calling CreateProcessAsUser...");

            Log(
                $"ApplicationName={executablePath}");

            Log(
                $"WorkingDirectory={workingDirectory}");

            Log(
                $"CreationFlags={creationFlags}");

            bool created =
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

            if (!created)
            {
                int error =
                    Marshal.GetLastWin32Error();

                Log(
                    $"ERROR: CreateProcessAsUser FAILED. " +
                    $"Win32={error}, " +
                    $"Message={new Win32Exception(error).Message}");

                return false;
            }


            // ==========================================
            // PROCESS CREATED
            // ==========================================

            Log(
                "CreateProcessAsUser SUCCESS!");

            Log(
                $"PID={processInfo.dwProcessId}");

            Log(
                $"ThreadID={processInfo.dwThreadId}");

            Log(
                $"Session={sessionId}");


            // ==========================================
            // CHECK PROCESS
            // ==========================================

            try
            {
                Process? process =
                    Process.GetProcessById(
                        (int)processInfo.dwProcessId);

                Log(
                    $"Process found immediately. " +
                    $"PID={process.Id}, " +
                    $"Name={process.ProcessName}");

                process.Dispose();
            }
            catch (Exception ex)
            {
                Log(
                    $"WARNING: Could not inspect created " +
                    $"process immediately: {ex.Message}");
            }


            // Даём процессу немного времени
            // и проверяем ещё раз.
            Thread.Sleep(500);

            try
            {
                Process? process =
                    Process.GetProcessById(
                        (int)processInfo.dwProcessId);

                Log(
                    $"Process still exists after 500ms. " +
                    $"PID={process.Id}, " +
                    $"Name={process.ProcessName}");

                process.Dispose();
            }
            catch
            {
                Log(
                    "Process no longer exists after 500ms.");
            }


            CloseHandle(
                processInfo.hThread);

            CloseHandle(
                processInfo.hProcess);

            Log(
                "--- LaunchForSession SUCCESS ---");

            return true;
        }
        catch (Exception ex)
        {
            Log(
                $"EXCEPTION in LaunchForSession: {ex}");

            return false;
        }
        finally
        {
            if (environment != IntPtr.Zero)
            {
                DestroyEnvironmentBlock(
                    environment);
            }

            if (primaryToken != IntPtr.Zero)
            {
                CloseHandle(
                    primaryToken);
            }

            if (userToken != IntPtr.Zero)
            {
                CloseHandle(
                    userToken);
            }
        }
    }
}