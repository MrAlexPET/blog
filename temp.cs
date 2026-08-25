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
                "1. UI ЗАПУЩЕН",
                "DEBUG",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);

            ApplicationConfiguration.Initialize();

            MessageBox.Show(
                "2. ApplicationConfiguration.Initialize() OK",
                "DEBUG",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);

            AuthenticationClient client =
                new AuthenticationClient();

            MessageBox.Show(
                "3. AuthenticationClient создан",
                "DEBUG",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);

            client.ShowLastAuthentication();

            MessageBox.Show(
                "4. ShowLastAuthentication() завершился",
                "DEBUG",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                ex.ToString(),
                "КРИТИЧЕСКАЯ ОШИБКА",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
    }
}