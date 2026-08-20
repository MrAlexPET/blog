private DateTime? FindPreviousAuthentication(string sid)
{
    try
    {
        string query = $@"
            <QueryList>
                <Query Id=""0"" Path=""Security"">
                    <Select Path=""Security"">
                        *[System[EventID=4624]]
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
            ReverseDirection = true
        };

        using EventLogReader reader =
            new EventLogReader(eventQuery);

        EventRecord? eventRecord;

        DateTime programStart = DateTime.Now;

        int foundEvents = 0;

        while ((eventRecord = reader.ReadEvent()) != null)
        {
            try
            {
                if (!eventRecord.TimeCreated.HasValue)
                    continue;

                string xml = eventRecord.ToXml();

                // Получаем LogonType через XML.
                int logonType = GetLogonType(xml);

                // Нас интересуют:
                //
                // 2  = Interactive
                // 10 = RemoteInteractive (RDP)

                if (logonType != 2 && logonType != 10)
                    continue;

                foundEvents++;

                DateTime eventTime = eventRecord.TimeCreated.Value;

                /*
                 * Если программа была запущена автоматически
                 * сразу после входа, самое новое событие 4624
                 * является текущим входом.
                 *
                 * Поэтому:
                 *
                 * 1. Если событие произошло совсем недавно
                 *    (например, менее 2 минут назад) —
                 *    считаем его текущим входом.
                 *
                 * 2. Тогда следующее событие будет предыдущим.
                 *
                 * Если программа запускается вручную,
                 * последнее событие старше 2 минут и поэтому
                 * оно считается последним входом.
                 */

                TimeSpan difference = programStart - eventTime;

                if (difference.TotalSeconds >= 0 &&
                    difference.TotalSeconds <= 120)
                {
                    // Это, скорее всего, текущий вход.
                    // Ищем следующий (предыдущий вход).

                    continue;
                }

                // Это последнее подходящее событие,
                // которое не является текущим входом.

                return eventTime;
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
            "Попробуйте запустить программу от имени администратора.",
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