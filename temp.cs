using System;
using System.Diagnostics.Eventing.Reader;
using System.Security.Principal;
using System.Windows.Forms;

namespace LastAuthentication
{
    public class AuthenticationManager
    {
        public void ProcessLogin()
        {
            try
            {
                WindowsIdentity identity = WindowsIdentity.GetCurrent();

                string sid = identity.User?.Value ?? "";
                string username = identity.Name;

                if (string.IsNullOrEmpty(sid))
                {
                    MessageBox.Show(
                        "Не удалось определить SID текущего пользователя.",
                        "Last Authentication",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );

                    return;
                }

                DateTime? previousLogin =
                    FindPreviousAuthentication(sid);

                // Временное диагностическое окно.
                // Оно поможет убедиться, что программа
                // действительно находит нужное событие.
                MessageBox.Show(
                    $"SID: {sid}\n" +
                    $"Пользователь: {username}\n\n" +
                    $"Найденное предыдущее время:\n" +
                    $"{(
                        previousLogin.HasValue
                            ? previousLogin.Value.ToString("dd.MM.yyyy HH:mm:ss")
                            : "НЕ НАЙДЕНО"
                    )}",
                    "DEBUG",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );

                if (previousLogin.HasValue)
                {
                    ShowLastAuthentication(
                        username,
                        previousLogin.Value
                    );
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    "Произошла ошибка:\n\n" +
                    ex.Message,
                    "Last Authentication",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
            }
        }

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
                    // Читать начиная с самых новых событий.
                    ReverseDirection = true
                };

                using EventLogReader reader =
                    new EventLogReader(eventQuery);

                EventRecord? eventRecord;

                DateTime programStart = DateTime.Now;

                while ((eventRecord = reader.ReadEvent()) != null)
                {
                    try
                    {
                        if (!eventRecord.TimeCreated.HasValue)
                            continue;

                        DateTime eventTime =
                            eventRecord.TimeCreated.Value;

                        string xml = eventRecord.ToXml();

                        // Получаем LogonType.
                        int logonType = GetLogonType(xml);

                        /*
                         * Типы входа:
                         *
                         * 2  = Interactive
                         * 10 = RemoteInteractive (RDP)
                         *
                         * Остальные типы нас пока не интересуют.
                         */

                        if (logonType != 2 &&
                            logonType != 10)
                        {
                            continue;
                        }

                        /*
                         * Если программа запускается автоматически
                         * сразу после входа, самое новое событие
                         * 4624 будет текущим входом.
                         *
                         * Поэтому если событие произошло менее
                         * 2 минут назад, пропускаем его и ищем
                         * следующее событие.
                         *
                         * Если программа запускается вручную,
                         * последнее событие обычно будет старше
                         * 2 минут и будет считаться последним
                         * входом.
                         */

                        TimeSpan difference =
                            programStart - eventTime;

                        if (difference.TotalSeconds >= 0 &&
                            difference.TotalSeconds <= 120)
                        {
                            continue;
                        }

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
                    "Попробуйте запустить программу " +
                    "от имени администратора.",
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

        private int GetLogonType(string xml)
        {
            try
            {
                const string startTag =
                    "<Data Name=\"LogonType\">";

                const string endTag =
                    "</Data>";

                int start =
                    xml.IndexOf(startTag);

                if (start == -1)
                    return -1;

                start += startTag.Length;

                int end =
                    xml.IndexOf(
                        endTag,
                        start
                    );

                if (end == -1)
                    return -1;

                string value =
                    xml.Substring(
                        start,
                        end - start
                    ).Trim();

                if (int.TryParse(
                    value,
                    out int logonType))
                {
                    return logonType;
                }
            }
            catch
            {
                // Если не удалось разобрать XML,
                // возвращаем неизвестный тип.
            }

            return -1;
        }

        private void ShowLastAuthentication(
            string username,
            DateTime authenticationTime)
        {
            MessageBox.Show(
                $"Пользователь:\n" +
                $"{username}\n\n" +

                $"Последняя успешная " +
                $"аутентификация:\n" +

                $"{authenticationTime:dd.MM.yyyy HH:mm:ss}",
                
                "Последняя аутентификация",

                MessageBoxButtons.OK,

                MessageBoxIcon.Information
            );
        }
    }
}