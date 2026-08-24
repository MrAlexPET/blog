using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;

namespace LastAuthentication.UI;

public class AuthenticationClient
{
    private const string PipeName = "LastAuthentication";

    public void ShowLastAuthentication()
    {
        try
        {
            using var pipe =
                new NamedPipeClientStream(
                    ".",
                    PipeName,
                    PipeDirection.InOut,
                    PipeOptions.None,
                    TokenImpersonationLevel.Impersonation);

            pipe.Connect(5000);

            using var reader =
                new StreamReader(
                    pipe,
                    Encoding.UTF8);

            string json =
                reader.ReadToEnd();

            if (string.IsNullOrWhiteSpace(json))
            {
                MessageBox.Show(
                    "Служба не вернула данные.",
                    "LastAuthentication",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);

                return;
            }

            PipeResponse? response =
                JsonSerializer.Deserialize<PipeResponse>(
                    json);

            if (response == null)
                return;

            if (!response.Success ||
                response.PreviousLogin == null)
            {
                MessageBox.Show(
                    "Предыдущая успешная аутентификация не найдена.",
                    "LastAuthentication",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);

                return;
            }

            MessageBox.Show(
                $"Последняя успешная аутентификация:\n\n" +
                $"{response.PreviousLogin:dd.MM.yyyy HH:mm:ss}",
                "Последняя аутентификация",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Ошибка подключения к службе:\n\n{ex.Message}",
                "LastAuthentication",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
    }
}

public class PipeResponse
{
    public bool Success { get; set; }

    public DateTime? PreviousLogin { get; set; }

    public int? PreviousLogonType { get; set; }
}