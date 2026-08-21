sc.exe create LastAuthenticationService binPath= "\"$PWD\LastAuthentication.Service.exe\"" start= auto obj= LocalSystem
Описание:
        Создание записи службы в реестре и в базе данных служб.
Использование:
        sc <сервер> create [имя службы] [binPath= ] <параметр1> <параметр2>...

Параметры:
Примечание. Имя параметра включает знак равенства (=).
      Между знаком равенства и значением параметра должен быть пробел.
 type= <own|share|interact|kernel|filesys|rec|userown|usershare>
       (по умолчанию = own)
 start= <boot|system|auto|demand|disabled|delayed-auto>
       (по умолчанию = demand)
 error= <normal|severe|critical|ignore>
       (по умолчанию = normal)
 binPath= <путь_к_двоичному_файлу_EXE>
 group= <группа_запуска>
 tag= <yes|no>
 depend= <зависимости (разделенные / (косой чертой))>
 obj= <имя_учетной_записи|имя_объекта>
       (по умолчанию = LocalSystem)
 DisplayName= <отображаемое имя>
 password= <пароль>
