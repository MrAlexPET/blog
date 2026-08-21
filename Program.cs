using System;
using System.Windows.Forms;

namespace LastAuthentication
{
    internal static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            ApplicationConfiguration.Initialize();

            var manager =
                new AuthenticationManager();

            manager.Run(args);
        }
    }
}