using System.Security.Principal;
using System.Text.Json;

namespace LastAuthentication.UI;

public class AuthenticationClient
{
    private readonly string _directory;

    public AuthenticationClient()
    {
        _directory = Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData),
            "LastAuthentication");
    }

    public void ShowLastAuthentication()
    {
        string sid =
            WindowsIdentity.GetCurrent()
                .User?
                .Value ?? "";

        if (string.IsNullOrEmpty(sid))
            return;

        string path =
            Path.Combine(
                _directory,
                sid.Replace("\\", "_")
                    .Replace("/", "_") +
                ".json");

        if (!File.Exists(path))
            return;

        try
        {
            string json =
                File.ReadAllText(path);

            StoredLogin? login =
                JsonSerializer.Deserialize<StoredLogin>(
                    json);

            if (login == null)
                return;

            /*
             * Пока служба хранит только последний
             * вход. Поэтому здесь временно
             * показываем его.
             */
            MessageBox.Show(
                $"Последняя успешная " +
                $"аутентификация:\n\n" +

                $"{login.LastLogin:dd.MM.yyyy HH:mm:ss}",

                "Последняя аутентификация",

                MessageBoxButtons.OK,

                MessageBoxIcon.Information
            );
        }
        catch
        {
        }
    }
}

public class StoredLogin
{
    public string Sid { get; set; } = "";

    public DateTime LastLogin { get; set; }

    public int LogonType { get; set; }

    public string LogonId { get; set; } = "";
}