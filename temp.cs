using System;
using System.IO;
using System.Text.Json;

namespace LastAuthentication
{
    public class LoginStorage
    {
        private readonly string _directory;

        public LoginStorage()
        {
            _directory = Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.CommonApplicationData
                ),
                "LastAuthentication"
            );

            Directory.CreateDirectory(_directory);
        }

        private string GetFilePath(string sid)
        {
            string safeSid =
                sid.Replace("\\", "_")
                   .Replace("/", "_");

            return Path.Combine(
                _directory,
                safeSid + ".json"
            );
        }

        public DateTime? GetLastLogin(string sid)
        {
            try
            {
                string path = GetFilePath(sid);

                if (!File.Exists(path))
                    return null;

                string json =
                    File.ReadAllText(path);

                LoginRecord? record =
                    JsonSerializer.Deserialize<LoginRecord>(
                        json
                    );

                return record?.LastLogin;
            }
            catch
            {
                return null;
            }
        }

        public void SaveLogin(
            string sid,
            DateTime loginTime)
        {
            try
            {
                string path =
                    GetFilePath(sid);

                LoginRecord record =
                    new LoginRecord
                    {
                        LastLogin = loginTime
                    };

                string json =
                    JsonSerializer.Serialize(
                        record,
                        new JsonSerializerOptions
                        {
                            WriteIndented = true
                        }
                    );

                File.WriteAllText(
                    path,
                    json
                );
            }
            catch
            {
                // Не ломаем вход пользователя,
                // если запись не удалась.
            }
        }

        private class LoginRecord
        {
            public DateTime LastLogin { get; set; }
        }
    }
}