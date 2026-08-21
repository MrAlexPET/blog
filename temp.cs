using Microsoft.Win32;
using System;

namespace LastAuthentication
{
    public class LoginStorage
    {
        private const string RegistryPath =
            @"Software\LastAuthentication";

        private const string LastLoginValue =
            "LastLogin";

        private const string LastLogonIdValue =
            "LastLogonId";

        private const string LastLogonTypeValue =
            "LastLogonType";

        public StoredLogin? GetLastLogin()
        {
            try
            {
                using RegistryKey? key =
                    Registry.CurrentUser.OpenSubKey(
                        RegistryPath,
                        writable: false
                    );

                if (key == null)
                    return null;

                object? timeValue =
                    key.GetValue(LastLoginValue);

                object? logonIdValue =
                    key.GetValue(LastLogonIdValue);

                object? logonTypeValue =
                    key.GetValue(LastLogonTypeValue);

                if (timeValue == null)
                    return null;

                if (!DateTime.TryParse(
                    timeValue.ToString(),
                    out DateTime lastLogin))
                {
                    return null;
                }

                return new StoredLogin
                {
                    LastLogin = lastLogin,

                    LastLogonId =
                        logonIdValue?.ToString() ?? "",

                    LastLogonType =
                        int.TryParse(
                            logonTypeValue?.ToString(),
                            out int type)
                            ? type
                            : -1
                };
            }
            catch
            {
                return null;
            }
        }

        public void SaveLogin(
            DateTime loginTime,
            string logonId,
            int logonType)
        {
            try
            {
                using RegistryKey key =
                    Registry.CurrentUser.CreateSubKey(
                        RegistryPath
                    );

                key.SetValue(
                    LastLoginValue,
                    loginTime.ToString("O")
                );

                key.SetValue(
                    LastLogonIdValue,
                    logonId
                );

                key.SetValue(
                    LastLogonTypeValue,
                    logonType,
                    RegistryValueKind.DWord
                );
            }
            catch
            {
                // Ошибка записи не должна
                // мешать пользователю войти в систему.
            }
        }

        public void Clear()
        {
            try
            {
                Registry.CurrentUser.DeleteSubKeyTree(
                    RegistryPath,
                    throwOnMissingSubKey: false
                );
            }
            catch
            {
            }
        }
    }

    public class StoredLogin
    {
        public DateTime LastLogin { get; set; }

        public string LastLogonId { get; set; } = "";

        public int LastLogonType { get; set; } = -1;
    }
}