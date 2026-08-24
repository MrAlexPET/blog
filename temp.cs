using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

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


    public static bool LaunchForActiveUser(
        string executablePath,
        ILogger logger)
    {
        try
        {
            if (!File.Exists(executablePath))
            {
                logger.LogError(
                    "UI executable not found: {Path}",
                    executablePath);

                return false;
            }

            logger.LogInformation(
                "SessionProcessLauncher started. UI path: {Path}",
                executablePath);

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

                logger.LogError(
                    "WTSEnumerateSessions failed. Win32 error: {Error}",
                    error);

                return false;
            }

            logger.LogInformation(
                "WTSEnumerateSessions succeeded. Sessions found: {Count}",
                count);

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

                    logger.LogInformation(
                        "Session found: SessionId={SessionId}, State={State}",
                        session.SessionId,
                        session.State);

                    if (session.State != WTSActive)
                    {
                        continue;
                    }

                    logger.LogInformation(
                        "Trying active session {SessionId}.",
                        session.SessionId);

                    try
                    {
                        if (LaunchForSession(
                                (uint)session.SessionId,
                                executablePath,
                                logger))
                        {
                            logger.LogInformation(
                                "UI successfully launched in session {SessionId}.",
                                session.SessionId);

                            return true;
                        }
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(
                            ex,
                            "Failed to launch UI in session {SessionId}.",
                            session.SessionId);
                    }
                }
            }
            finally
            {
                WTSFreeMemory(
                    sessionInfoPtr);
            }

            logger.LogWarning(
                "No active session could be used to launch UI.");

            return false;
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "Unexpected error in LaunchForActiveUser.");

            return false;
        }
    }


    private static bool LaunchForSession(
        uint sessionId,
        string executablePath,
        ILogger logger)
    {
        IntPtr userToken = IntPtr.Zero;
        IntPtr primaryToken = IntPtr.Zero;
        IntPtr environment = IntPtr.Zero;

        try
        {
            logger.LogInformation(
                "Calling WTSQueryUserToken for session {SessionId}.",
                sessionId);

            if (!WTSQueryUserToken(
                    sessionId,
                    out userToken))
            {
                int error =
                    Marshal.GetLastWin32Error();

                logger.LogError(
                    "WTSQueryUserToken FAILED. Session={SessionId}, Win32 error={Error}, Message={Message}",
                    sessionId,
                    error,
                    new Win32Exception(error).Message);

                return false;
            }

            logger.LogInformation(
                "WTSQueryUserToken succeeded. Session={SessionId}.",
                sessionId);


            logger.LogInformation(
                "Calling DuplicateTokenEx.");

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

                logger.LogError(
                    "DuplicateTokenEx FAILED. Win32 error={Error}, Message={Message}",
                    error,
                    new Win32Exception(error).Message);

                return false;
            }

            logger.LogInformation(
                "DuplicateTokenEx succeeded.");


            logger.LogInformation(
                "Calling CreateEnvironmentBlock.");

            if (!CreateEnvironmentBlock(
                    out environment,
                    primaryToken,
                    false))
            {
                int error =
                    Marshal.GetLastWin32Error();

                logger.LogError(
                    "CreateEnvironmentBlock FAILED. Win32 error={Error}, Message={Message}",
                    error,
                    new Win32Exception(error).Message);

                return false;
            }

            logger.LogInformation(
                "CreateEnvironmentBlock succeeded.");


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


            var processInfo =
                new PROCESS_INFORMATION();

            uint creationFlags =
                CREATE_UNICODE_ENVIRONMENT |
                CREATE_NEW_CONSOLE;


            logger.LogInformation(
                "Calling CreateProcessAsUser. Path={Path}, Session={SessionId}.",
                executablePath,
                sessionId);

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

                logger.LogError(
                    "CreateProcessAsUser FAILED. Win32 error={Error}, Message={Message}",
                    error,
                    new Win32Exception(error).Message);

                return false;
            }


            logger.LogInformation(
                "PROCESS CREATED successfully. PID={Pid}, Session={SessionId}.",
                processInfo.dwProcessId,
                sessionId);


            CloseHandle(
                processInfo.hThread);

            CloseHandle(
                processInfo.hProcess);

            return true;
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "Exception while launching process in session {SessionId}.",
                sessionId);

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