using System.ComponentModel;
using System.Runtime.InteropServices;

namespace LastAuthentication.Service;

public static class SessionProcessLauncher
{
    private const uint TOKEN_QUERY = 0x0008;
    private const uint TOKEN_DUPLICATE = 0x0002;
    private const uint TOKEN_ASSIGN_PRIMARY = 0x0001;

    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint CREATE_NEW_CONSOLE = 0x00000010;

    private const int STARTF_USESHOWWINDOW = 0x00000001;
    private const short SW_SHOWNORMAL = 1;

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
        "kernel32.dll",
        SetLastError = true)]
    private static extern uint WTSGetActiveConsoleSessionId();

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

        uint sessionId =
            WTSGetActiveConsoleSessionId();

        Console.WriteLine(
            $"[SessionProcessLauncher] Active console session: {sessionId}");

        if (sessionId == 0xFFFFFFFF)
        {
            Console.WriteLine(
                "[SessionProcessLauncher] No active console session.");

            return false;
        }

        return LaunchForSession(
            sessionId,
            executablePath);
    }


    public static bool LaunchForSession(
        uint sessionId,
        string executablePath)
    {
        IntPtr userToken = IntPtr.Zero;
        IntPtr primaryToken = IntPtr.Zero;
        IntPtr environment = IntPtr.Zero;

        try
        {
            Console.WriteLine(
                $"[SessionProcessLauncher] Launching for session {sessionId}");

            Console.WriteLine(
                $"[SessionProcessLauncher] EXE: {executablePath}");


            // -------------------------------------------------
            // USER TOKEN
            // -------------------------------------------------

            if (!WTSQueryUserToken(
                    sessionId,
                    out userToken))
            {
                int error =
                    Marshal.GetLastWin32Error();

                Console.WriteLine(
                    $"[SessionProcessLauncher] WTSQueryUserToken FAILED: {error}");

                throw new Win32Exception(
                    error,
                    "WTSQueryUserToken failed.");
            }

            Console.WriteLine(
                "[SessionProcessLauncher] WTSQueryUserToken OK");


            // -------------------------------------------------
            // PRIMARY TOKEN
            // -------------------------------------------------

            if (!DuplicateTokenEx(
                    userToken,
                    TOKEN_QUERY |
                    TOKEN_DUPLICATE |
                    TOKEN_ASSIGN_PRIMARY,
                    IntPtr.Zero,
                    2,
                    1,
                    out primaryToken))
            {
                int error =
                    Marshal.GetLastWin32Error();

                Console.WriteLine(
                    $"[SessionProcessLauncher] DuplicateTokenEx FAILED: {error}");

                throw new Win32Exception(
                    error,
                    "DuplicateTokenEx failed.");
            }

            Console.WriteLine(
                "[SessionProcessLauncher] DuplicateTokenEx OK");


            // -------------------------------------------------
            // ENVIRONMENT
            // -------------------------------------------------

            if (!CreateEnvironmentBlock(
                    out environment,
                    primaryToken,
                    false))
            {
                int error =
                    Marshal.GetLastWin32Error();

                Console.WriteLine(
                    $"[SessionProcessLauncher] CreateEnvironmentBlock FAILED: {error}");

                throw new Win32Exception(
                    error,
                    "CreateEnvironmentBlock failed.");
            }

            Console.WriteLine(
                "[SessionProcessLauncher] CreateEnvironmentBlock OK");


            // -------------------------------------------------
            // STARTUP INFO
            // -------------------------------------------------

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


            // -------------------------------------------------
            // CREATE PROCESS
            // -------------------------------------------------

            var processInfo =
                new PROCESS_INFORMATION();

            uint creationFlags =
                CREATE_UNICODE_ENVIRONMENT |
                CREATE_NEW_CONSOLE;


            bool result =
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


            if (!result)
            {
                int error =
                    Marshal.GetLastWin32Error();

                Console.WriteLine(
                    $"[SessionProcessLauncher] CreateProcessAsUser FAILED: {error}");

                throw new Win32Exception(
                    error,
                    "CreateProcessAsUser failed.");
            }


            Console.WriteLine(
                $"[SessionProcessLauncher] PROCESS CREATED. PID={processInfo.dwProcessId}, SESSION={sessionId}");


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
