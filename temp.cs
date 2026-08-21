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

    /*
     * После показа диагностической информации
     * сохраняем текущий вход.
     *
     * Поэтому следующий запуск --test
     * уже увидит его как предыдущий.
     */
    _storage.SaveLogin(
        sid,
        login.Time
    );
}