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

    public StoredLogin? Get(string sid)
    {
        try
        {
            string path =
                GetFilePath(sid);

            if (!File.Exists(path))
                return null;

            string json =
                File.ReadAllText(path);

            return JsonSerializer.Deserialize<StoredLogin>(
                json);
        }
        catch
        {
            return null;
        }
    }

    public void Save(
        string sid,
        DateTime time,
        int logonType,
        string logonId)
    {
        try
        {
            string path =
                GetFilePath(sid);

            StoredLogin login =
                new StoredLogin
                {
                    Sid = sid,
                    LastLogin = time,
                    LogonType = logonType,
                    LogonId = logonId
                };

            string json =
                JsonSerializer.Serialize(
                    login,
                    new JsonSerializerOptions
                    {
                        WriteIndented = true
                    });

            File.WriteAllText(
                path,
                json);
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