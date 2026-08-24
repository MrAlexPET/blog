using System.Text.Json;

namespace LastAuthentication.Service;

public class LoginStorage
{
    private readonly string _directory;

    public LoginStorage()
    {
        _directory = Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData),
            "LastAuthentication");

        Directory.CreateDirectory(_directory);
    }

    private string GetFilePath(string sid)
    {
        string safeSid =
            sid.Replace("\\", "_")
               .Replace("/", "_");

        return Path.Combine(
            _directory,
            safeSid + ".json");
    }

    public LoginHistory? Get(string sid)
    {
        try
        {
            string path = GetFilePath(sid);

            if (!File.Exists(path))
                return null;

            string json =
                File.ReadAllText(path);

            return JsonSerializer.Deserialize<LoginHistory>(
                json);
        }
        catch
        {
            return null;
        }
    }

    public void Save(
        string sid,
        DateTime currentLogin,
        int currentLogonType,
        string currentLogonId)
    {
        try
        {
            LoginHistory? old =
                Get(sid);

            LoginHistory history =
                new LoginHistory
                {
                    Sid = sid,

                    PreviousLogin =
                        old?.CurrentLogin,

                    PreviousLogonType =
                        old?.CurrentLogonType,

                    PreviousLogonId =
                        old?.CurrentLogonId,

                    CurrentLogin =
                        currentLogin,

                    CurrentLogonType =
                        currentLogonType,

                    CurrentLogonId =
                        currentLogonId
                };

            string json =
                JsonSerializer.Serialize(
                    history,
                    new JsonSerializerOptions
                    {
                        WriteIndented = true
                    });

            File.WriteAllText(
                GetFilePath(sid),
                json);
        }
        catch
        {
        }
    }
}

public class LoginHistory
{
    public string Sid { get; set; } = "";

    public DateTime? PreviousLogin { get; set; }

    public int? PreviousLogonType { get; set; }

    public string? PreviousLogonId { get; set; }

    public DateTime CurrentLogin { get; set; }

    public int CurrentLogonType { get; set; }

    public string CurrentLogonId { get; set; } = "";
}