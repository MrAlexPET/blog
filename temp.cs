using System.ComponentModel;
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

    [DllImport(
        "wtsapi32.dll")]
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


    public static bool LaunchForActiveUser(
        string executablePath)
    {
        if (!File.Exists(executablePath))
        {
            throw new FileNotFoundException(
                "UI executable not found.",
                executablePath);
        }

        Console.WriteLine(
            $"[SessionProcessLauncher] Searching active sessions...");

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
            int error =
                Marshal.GetLastWin32Error();

            throw new Win32Exception(
                error,
                "WTSEnumerateSessions failed.");
        }

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

                Console.WriteLine(
                    $"[SessionProcessLauncher] Session={session.SessionId}, State={session.State}");

                /*
                 * Нас интересуют только активные
                 * пользовательские сессии.
                 */
                if (session.State != WTSActive)
                {
                    continue;
                }

                Console.WriteLine(
                    $"[SessionProcessLauncher] Trying session {session.SessionId}");

                try
                {
                    if (LaunchForSession(
                            (uint)session.SessionId,
                            executablePath))
                    {
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(
                        $"[SessionProcessLauncher] Session {session.SessionId} failed:");

                    Console.WriteLine(ex.ToString());
                }
            }
        }
        finally
        {
            WTSFreeMemory(
                sessionInfoPtr);
        }

        return false;
    }


    private static bool LaunchForSession(
        uint sessionId,
        string executablePath)
    {
        IntPtr userToken = IntPtr.Zero;
        IntPtr primaryToken = IntPtr.Zero;
        IntPtr environment = IntPtr.Zero;

        try
        {
            Console.WriteLine(
                $"[SessionProcessLauncher] WTSQueryUserToken({sessionId})");

            if (!WTSQueryUserToken(
                    sessionId,
                    out userToken))
            {
                int error =
                    Marshal.GetLastWin32Error();

                throw new Win32Exception(
                    error,
                    $"WTSQueryUserToken failed for session {sessionId}.");
            }

            Console.WriteLine(
                "[SessionProcessLauncher] User token acquired.");


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

                throw new Win32Exception(
                    error,
                    "DuplicateTokenEx failed.");
            }

            Console.WriteLine(
                "[SessionProcessLauncher] Primary token created.");


            if (!CreateEnvironmentBlock(
                    out environment,
                    primaryToken,
                    false))
            {
                int error =
                    Marshal.GetLastWin32Error();

                throw new Win32Exception(
                    error,
                    "CreateEnvironmentBlock failed.");
            }

            Console.WriteLine(
                "[SessionProcessLauncher] User environment created.");


            var startupInfo =
                new STARTUPINFO();

            startupInfo.cb =
                (uint)Marshal.SizeOf<STARTUPINFO>();

            /*
             * Критически важно:
             *
             * это заставляет GUI-процесс работать
             * на интерактивном пользовательском
             * рабочем столе.
             */
            startupInfo.lpDesktop =
                @"winsta0\default";

            startupInfo.dwFlags =
                STARTF_USESHOWWINDOW;

            startupInfo.wShowWindow =
                SW_SHOWNORMAL;


            var processInfo =
                new PROCESS_INFORMATION();


            uint creationFlags =
                CREATE_UNICODE_ENVIRONMENT |
                CREATE_NEW_CONSOLE;


            Console.WriteLine(
                $"[SessionProcessLauncher] Creating UI process: {executablePath}");


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
                    Path.GetDirectoryName(
                        executablePath),
                    ref startupInfo,
                    out processInfo);


            if (!created)
            {
                int error =
                    Marshal.GetLastWin32Error();

                throw new Win32Exception(
                    error,
                    "CreateProcessAsUser failed.");
            }


            Console.WriteLine(
                $"[SessionProcessLauncher] UI CREATED. PID={processInfo.dwProcessId}, Session={sessionId}");


            CloseHandle(
                processInfo.hThread);

            CloseHandle(
                processInfo.hProcess);


            return true;
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
