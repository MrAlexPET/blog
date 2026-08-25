using System;
using System.Windows.Forms;

namespace LastAuthentication.UI;

internal static class Program
{
    [STAThread]
    static void Main()
    {
        ApplicationConfiguration.Initialize();

        AuthenticationClient client =
            new AuthenticationClient();

        client.ShowLastAuthentication();
    }
}