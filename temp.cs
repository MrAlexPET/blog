using System;
using System.Windows.Forms;

namespace LastAuthentication.UI;

internal static class Program
{
    [STAThread]
    static void Main()
    {
        try
        {
            MessageBox.Show(
                "UI ЗАПУЩЕН!",
                "LastAuthentication DEBUG",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);

            ApplicationConfiguration.Initialize();

            AuthenticationClient client =
                new AuthenticationClient();

            client.ShowLastAuthentication();
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                ex.ToString(),
                "КРИТИЧЕСКАЯ ОШИБКА LastAuthentication.UI",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
    }
}