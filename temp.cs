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

            string sid =
                identity.User?.Value ?? "";

            if (string.IsNullOrEmpty(sid))
            {
                return;
            }

            /*
             * --test
             *
             * Ручной тест программы.
             */
            if (Array.Exists(
                args,
                x => string.Equals(
                    x,
                    "--test",
                    StringComparison.OrdinalIgnoreCase)))
            {
                RunTest(
                    username,
                    sid
                );

                return;
            }

            /*
             * Добавляем программу
             * в автозапуск.
             */
            _startup.EnableStartup();

            /*
             * Ищем текущую аутентификацию.
             */
            LoginInfo? currentLogin =
                _detector.FindCurrentLogin();

            if (currentLogin == null)
            {
                return;
            }

            /*
             * Получаем последнее сохранённое
             * время входа.
             */
            DateTime? previousLogin =
                _storage.GetLastLogin(sid);

            /*
             * Если это первый запуск,
             * просто сохраняем время.
             */
            if (!previousLogin.HasValue)
            {
                _storage.SaveLogin(
                    sid,
                    currentLogin.Time
                );

                return;
            }

            /*
             * Показываем пользователю
             * предыдущий вход.
             */
            ShowLastLogin(
                username,
                previousLogin.Value,
                currentLogin.Type
            );

            /*
             * После закрытия окна
             * сохраняем текущий вход.
             */
            _storage.SaveLogin(
                sid,
                currentLogin.Time
            );

            /*
             * Программа заканчивает работу.
             */
        }

        private void ShowLastLogin(
            string username,
            DateTime previousLogin,
            LoginType currentLoginType)
        {
            string loginTypeText =
                currentLoginType switch
                {
                    LoginType.Rdp =>
                        "Удалённый вход (RDP)",

                    LoginType.Local =>
                        "Локальный вход",

                    _ =>
                        "Вход"
                };

            MessageBox.Show(
                $"Пользователь:\n{username}\n\n" +

                $"Последняя успешная " +
                $"аутентификация:\n" +

                $"{previousLogin:dd.MM.yyyy HH:mm:ss}\n\n" +

                $"Текущий тип входа:\n" +

                $"{loginTypeText}",

                "Последняя аутентификация",

                MessageBoxButtons.OK,

                MessageBoxIcon.Information
            );
        }

        private void RunTest(
            string username,
            string sid)
        {
            LoginInfo? login =
                _detector.FindCurrentLogin();

            if (login == null)
            {
                MessageBox.Show(
                    "Текущая аутентификация " +
                    "не найдена.",
                    "Тест",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning
                );

                return;
            }

            DateTime? previous =
                _storage.GetLastLogin(sid);

            string message =
                $"Пользователь:\n{username}\n\n" +

                $"SID:\n{sid}\n\n" +

                $"Текущий вход:\n" +

                $"{login.Time:dd.MM.yyyy HH:mm:ss.fff}\n\n" +

                $"Тип:\n" +

                $"{login.Type}\n\n" +

                $"Logon ID:\n" +

                $"{login.LogonId}\n\n" +

                $"Предыдущий сохранённый вход:\n" +

                (
                    previous.HasValue
                        ? previous.Value.ToString(
                            "dd.MM.yyyy HH:mm:ss.fff")
                        : "НЕТ"
                );

            MessageBox.Show(
                message,
                "Last Authentication - TEST",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information
            );
        }
    }
}