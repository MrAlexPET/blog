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

    /*
     * ВАЖНО:
     *
     * WTSGetActiveConsoleSessionId находится
     * в kernel32.dll.
     */
    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    private static extern uint WTSGetActiveConsoleSessionId();

    /*
     * WTSQueryUserToken находится в wtsapi32.dll.
     */
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

        if (sessionId == 0xFFFFFFFF)
        {
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
            /*
             * Получаем токен пользователя,
             * работающего в указанной сессии.
             */
            if (!WTSQueryUserToken(
                    sessionId,
                    out userToken))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "WTSQueryUserToken failed.");
            }


            /*
             * Преобразуем impersonation token
             * в primary token.
             */
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
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "DuplicateTokenEx failed.");
            }


            /*
             * Создаём окружение пользователя.
             */
            if (!CreateEnvironmentBlock(
                    out environment,
                    primaryToken,
                    false))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "CreateEnvironmentBlock failed.");
            }


            var startupInfo =
                new STARTUPINFO();

            startupInfo.cb =
                (uint)Marshal.SizeOf<STARTUPINFO>();

            /*
             * Очень важно:
             * запускаем процесс на обычном
             * пользовательском рабочем столе.
             */
            startupInfo.lpDesktop =
                @"winsta0\default";

            startupInfo.dwFlags =
                STARTF_USESHOWWINDOW;

            startupInfo.wShowWindow =
                SW_SHOWNORMAL;


            PROCESS_INFORMATION processInfo;


            uint creationFlags =
                CREATE_UNICODE_ENVIRONMENT |
                CREATE_NEW_CONSOLE;


            /*
             * Создаём UI-процесс от имени
             * вошедшего пользователя.
             */
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
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "CreateProcessAsUser failed.");
            }


            /*
             * Дескрипторы нам больше не нужны.
             */
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