using System;
using System.Security.Principal;
using System.Windows.Forms;

namespace LastAuthentication
{
    public class AuthenticationManager
    {
        private readonly LoginDetector _detector;

        private readonly LoginStorage _storage;

        private readonly StartupManager _startup;

        public AuthenticationManager()
        {
            _detector =
                new LoginDetector();

            _storage =
                new LoginStorage();

            _startup =
                new StartupManager();
        }

        public void Run(string[] args)
        {
            WindowsIdentity identity =
                WindowsIdentity.GetCurrent();

            string username =
                identity.Name;

            /*
             * Тестовый режим.
             */
            if (HasArgument(
                args,
                "--test"))
            {
                RunTest(username);

                return;
            }

            /*
             * Включаем автозапуск.
             */
            _startup.EnableStartup();

            /*
             * Определяем текущий вход.
             */
            LoginInfo? currentLogin =
                _detector.FindCurrentLogin();

            if (currentLogin == null)
            {
                return;
            }

            /*
             * Получаем предыдущий вход.
             */
            StoredLogin? previousLogin =
                _storage.GetLastLogin();

            /*
             * Если это первая авторизация
             * после установки программы,
             * просто сохраняем её.
             */
            if (previousLogin == null)
            {
                _storage.SaveLogin(
                    currentLogin.Time,
                    currentLogin.LogonId,
                    currentLogin.LogonType
                );

                return;
            }

            /*
             * Если Windows каким-либо образом
             * запустила программу повторно
             * в рамках той же самой logon-сессии,
             * ничего не показываем.
             */
            if (!string.IsNullOrEmpty(
                    previousLogin.LastLogonId) &&
                string.Equals(
                    previousLogin.LastLogonId,
                    currentLogin.LogonId,
                    StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            /*
             * Показываем информацию
             * о предыдущем входе.
             */
            ShowLastLogin(
                username,
                previousLogin.LastLogin,
                currentLogin.Type
            );

            /*
             * После нажатия OK сохраняем
             * текущий вход.
             */
            _storage.SaveLogin(
                currentLogin.Time,
                currentLogin.LogonId,
                currentLogin.LogonType
            );

            /*
             * После этого Main()
             * заканчивается, и процесс
             * полностью завершается.
             */
        }

        private void ShowLastLogin(
            string username,
            DateTime lastLogin,
            LoginType currentLoginType)
        {
            string loginType =
                currentLoginType switch
                {
                    LoginType.Local =>
                        "Локальный вход",

                    LoginType.Rdp =>
                        "Удалённый вход (RDP)",

                    _ =>
                        "Вход"
                };

            MessageBox.Show(
                $"Пользователь:\n" +
                $"{username}\n\n" +

                $"Последняя успешная " +
                $"аутентификация:\n" +

                $"{lastLogin:dd.MM.yyyy HH:mm:ss}\n\n" +

                $"Текущий вход:\n" +

                $"{loginType}",

                "Последняя аутентификация",

                MessageBoxButtons.OK,

                MessageBoxIcon.Information
            );
        }

        private void RunTest(
            string username)
        {
            LoginInfo? currentLogin =
                _detector.FindCurrentLogin();

            if (currentLogin == null)
            {
                MessageBox.Show(
                    "Текущая аутентификация " +
                    "не найдена.",

                    "Last Authentication",

                    MessageBoxButtons.OK,

                    MessageBoxIcon.Warning
                );

                return;
            }

            StoredLogin? previousLogin =
                _storage.GetLastLogin();

            string previousText =
                previousLogin == null
                    ? "НЕТ"
                    : previousLogin.LastLogin
                        .ToString(
                            "dd.MM.yyyy HH:mm:ss.fff"
                        );

            string message =
                $"Пользователь:\n" +
                $"{username}\n\n" +

                $"Текущий вход:\n" +
                $"{currentLogin.Time:dd.MM.yyyy HH:mm:ss.fff}\n\n" +

                $"Logon Type:\n" +
                $"{currentLogin.LogonType}\n\n" +

                $"Тип входа:\n" +
                $"{currentLogin.Type}\n\n" +

                $"Current Logon ID:\n" +
                $"{currentLogin.LogonId}\n\n" +

                $"Предыдущий сохранённый вход:\n" +
                $"{previousText}";

            MessageBox.Show(
                message,

                "Last Authentication - TEST",

                MessageBoxButtons.OK,

                MessageBoxIcon.Information
            );

            /*
             * В тестовом режиме также сохраняем
             * текущий вход.
             *
             * Это позволяет тестировать:
             *
             * Login #1
             * ↓
             * --test
             *
             * Login #2
             * ↓
             * --test
             *
             * и увидеть Login #1 как предыдущий.
             */
            _storage.SaveLogin(
                currentLogin.Time,
                currentLogin.LogonId,
                currentLogin.LogonType
            );
        }

        private bool HasArgument(
            string[] args,
            string argument)
        {
            foreach (string arg in args)
            {
                if (string.Equals(
                    arg,
                    argument,
                    StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
