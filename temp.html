private DateTime? FindPreviousAuthentication(string sid)
{
    try
    {
        string query = $@"
            <QueryList>
                <Query Id=""0"" Path=""Security"">
                    <Select Path=""Security"">
                        *[System[
                            EventID=4624
                        ]]
                        and
                        *[EventData[
                            Data[@Name='TargetUserSid'] = '{sid}'
                        ]]
                    </Select>
                </Query>
            </QueryList>";

        EventLogQuery eventQuery = new EventLogQuery(
            "Security",
            PathType.LogName,
            query
        )
        {
            // Читать события начиная с самого нового
            ReverseDirection = true
        };

        using EventLogReader reader =
            new EventLogReader(eventQuery);

        EventRecord? eventRecord;

        int validLogonsFound = 0;

        while ((eventRecord = reader.ReadEvent()) != null)
        {
            try
            {
                // Получаем XML события
                string xml = eventRecord.ToXml();

                // Проверяем тип входа.
                //
                // 2  = Interactive
                // 10 = RemoteInteractive (RDP)
                //
                // Нас интересуют именно эти типы.

                bool isInteractive =
                    xml.Contains(
                        "<Data Name=\"LogonType\">2</Data>"
                    ) ||
                    xml.Contains(
                        "<Data Name=\"LogonType\">10</Data>"
                    );

                if (!isInteractive)
                    continue;

                validLogonsFound++;

                // Самое новое подходящее событие —
                // текущий вход.
                //
                // Второе — предыдущий.

                if (validLogonsFound == 2)
                {
                    return eventRecord.TimeCreated;
                }
            }
            finally
            {
                eventRecord.Dispose();
            }
        }

        return null;
    }
    catch (UnauthorizedAccessException)
    {
        MessageBox.Show(
            "Нет доступа к журналу Security.\n\n" +
            "Запустите программу от имени администратора " +
            "или настройте необходимые права.",
            "Last Authentication",
            MessageBoxButtons.OK,
            MessageBoxIcon.Warning
        );

        return null;
    }
    catch (Exception ex)
    {
        MessageBox.Show(
            "Ошибка чтения журнала Security:\n\n" +
            ex.Message,
            "Last Authentication",
            MessageBoxButtons.OK,
            MessageBoxIcon.Error
        );

        return null;
    }
}