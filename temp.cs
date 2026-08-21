using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;

namespace LastAuthentication
{
    public class StartupManager
    {
        private const string RunKey =
            @"Software\Microsoft\Windows\CurrentVersion\Run";

        private const string AppName =
            "LastAuthentication";

        public void EnableStartup()
        {
            try
            {
                string exePath =
                    Process.GetCurrentProcess()
                        .MainModule!
                        .FileName!;

                using RegistryKey? key =
                    Registry.CurrentUser.OpenSubKey(
                        RunKey,
                        writable: true
                    );

                if (key == null)
                    return;

                key.SetValue(
                    AppName,
                    $"\"{exePath}\""
                );
            }
            catch
            {
                // Ничего не делаем.
            }
        }

        public void DisableStartup()
        {
            try
            {
                using RegistryKey? key =
                    Registry.CurrentUser.OpenSubKey(
                        RunKey,
                        writable: true
                    );

                key?.DeleteValue(
                    AppName,
                    throwOnMissingValue: false
                );
            }
            catch
            {
            }
        }

        public bool IsStartupEnabled()
        {
            try
            {
                using RegistryKey? key =
                    Registry.CurrentUser.OpenSubKey(
                        RunKey,
                        writable: false
                    );

                object? value =
                    key?.GetValue(AppName);

                return value != null;
            }
            catch
            {
                return false;
            }
        }
    }
}