
# Распространенные уязвимости веб-приложений

[OWASP](https://www.perforce.com/blog/kw/what-is-owasp-top-10)
OWASP - Open Web Application Security Project. [OWASP Top 10](https://owasp.org/www-project-top-ten/) - в этом документе представлена ​​информация о 10 наиболее важных угрозах безопасности приложений на момент проведения исследования. Эти риски представляют собой эксплойты, которые чаще всего используются хакерами и наносят наибольший ущерб.


## 1. Broken authentication (Broken Access Control)

Каждая часть информации должна быть доступна только определенному кругу пользователей в зависимости от предоставленного им доступа. Нарушение контроля доступа может привести к ситуациям, когда пользователи смогут получить доступ к информации, к которой у них нет полномочий.

Например, если обычный пользователь может получить доступ к странице администратора, даже если он не является администратором, его роль не была проверена должным образом. Этот риск безопасности можно снизить путем внедрения модели управления доступом на основе владения записями.

Нарушение аутентификации связано с различными веб-уязвимостями. Однако все они подразумевают обход методов аутентификации, представленных на веб-сайтах. Большинство атак с нарушенной аутентификацией включают заполнение учетных данных, неправильные таймауты сеанса, а также witout solt и хешированные пароли. Это позволяет злоумышленникам обходить аутентификацию и выдавать себя за законных пользователей.

Многофакторная аутентификация — один из лучших способов борьбы с атаками со сбоем аутентификации. Следовательно, знания учетных данных пользователя — имени пользователя и пароля — будет недостаточно для доступа к его учетной записи. Кроме того, пароли пользователей, хранящиеся в вашей базе данных, должны быть не только зашифрованы, но и обработаны solt и хешированы.

## 2. Cryptographic Failures

Криптографические сбои, ранее известные как раскрытие конфиденциальных данных, сосредоточены на сбоях, связанных с криптографией. Вместо того чтобы напрямую атаковать систему, хакеры часто пытаются украсть данные, пока они передаются из браузера пользователя. Чтобы предотвратить подобные атаки, вам необходимо создать безопасный канал связи.

Для веб-приложений быстрым решением этой проблемы является принудительное применение TLS на всех страницах. Без принудительной политики TLS или с плохим шифрованием хакер может отслеживать сетевой трафик, понижать качество соединения с HTTPS до HTTP и перехватывать всю информацию, передаваемую в виде открытого текста: пользовательские данные, пароли, файлы cookie сеанса и т. д.

## 3. Injection (SQL-инъекция)

SQL-инъекция — это веб-атака с использованием вредоносных операторов SQL. При успешной SQL-атаке хакер может получить доступ к базе данных SQL вашего веб-сайта, чтобы копировать, добавлять, редактировать или удалять содержащиеся в ней данные. SQL-инъекция — наиболее распространенная уязвимость веб-безопасности, поскольку большинство веб-сайтов используют базу данных SQL.

Вы можете справиться с внедрением SQL , соблюдая осторожность при вводе данных пользователем. Идеально не полагаться на какой-либо пользовательский ввод. Прежде чем разрешить ввод данных на своем сайте, убедитесь, что все введенные пользователем данные проверены.

Предотвращение использования слабых паролей пользователями и ограничение неудачных попыток входа в систему эффективно защищают большинство учетных записей пользователей от этой уязвимости. Вам также необходимо установить таймауты сеансов и внедрить системы восстановления учетных данных, чтобы помочь пользователям защитить свои учетные записи от непреднамеренных ошибок и без труда восстановить их.

Кроме того, к этому типу уязвимостей теперь относятся CWE, которые больше связаны со сбоями идентификации и Cross-site scripting теперь входят в эту категорию.

#### Cross-Site Scripting

Эта веб-уязвимость, также известная как XSS-атаки, связана с внедрением кода на стороне клиента. Обычно при атаке на веб-страницу вставляется вредоносный код, который будет выполняться при посещении веб-страницы. Это уязвимость ввода, которая в основном возникает на веб-сайтах, допускающих обратную связь с пользователем.

Как и SQL-инъекция, проблему XSS можно решить путем мониторинга ввода данных пользователем. Каждый пользовательский ввод должен фильтроваться, и разрешаться должны только безопасные и действительные записи. Кроме того, вы можете кодировать выходные данные и использовать политику безопасности контента (CSP). Эта политика может помочь уменьшить ущерб, который может нанести XSS-атака.

[потрясающая шпаргалка по векторам XSS для поиска XSS](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
  
## 4. Insecure Design
 
Небезопасный дизайн относится к рискам, связанным с недостатками проектирования, которые часто включают отсутствие хотя бы одного из следующих факторов:

- Моделирование угроз
- Безопасные шаблоны проектирования
- Принципы безопасного проектирования
- Эталонная архитектура

## 5. Security Misconfiguration

Учитывая все больший интерес к программному обеспечению с широкими возможностями настройки, неудивительно, что эта категория поднимается вверх. 

Неправильные настройки конфигурации безопасности часто являются результатом:

- Небезопасные конфигурации по умолчанию.
- Неполные или импровизированные конфигурации.
- Открытое облачное хранилище.
- Неправильно настроены HTTP-заголовки.
- Многословные сообщения об ошибках, содержащие конфиденциальную информацию.

## 6. Vulnerable and Outdated Components

Уязвимые и устаревшие компоненты
Компоненты состоят из библиотек, фреймворков и других программных модулей. Часто компоненты работают с теми же привилегиями, что и ваше приложение. Если компонент уязвим, он может быть использован ненадежным агентом. Это приводит к серьезной потере данных или захвату сервера.

## 7. Identification and Authentication Failures

Функции приложения аутентификации и управления сеансом должны быть реализованы правильно. В противном случае это создает уязвимость программного обеспечения, которую могут использовать ненадежные агенты для получения доступа к личной информации.

## 8. Software and Data Integrity Failures

Нарушения целостности программного обеспечения и данных
Нарушения целостности программного обеспечения и данных относятся к предположениям, сделанным в отношении обновлений программного обеспечения, критических данных и конвейеров CI/CD без проверки целостности. Кроме того, ошибки десериализации часто приводят к удаленному выполнению кода. Это позволяет ненадежным агентам выполнять атаки воспроизведения, внедрения и повышения привилегий.
 
Кроме того, в состав этой уязвимости включена небезопасная десериализация. Небезопасная десериализация относится к любому приложению, которое не десериализует внешние или умеренные объекты, которые являются уязвимыми. Это связано с тем, что хакеры получают возможность манипулировать данными, получаемыми внутренним кодом.

Самый быстрый и, возможно, самый безопасный способ защитить себя от [небезопасной десериализации](https://www.youtube.com/watch?v=jwzeJU_62IQ) — просто не принимать сериализованные объекты из ненадежных источников и ограничить использование сериализованных объектов в вашем приложении.

## 9. Security Logging and Monitoring Failures

Сбои ведения журнала безопасности и мониторинга
Недостаточные процессы регистрации и мониторинга опасны. Это делает ваши данные уязвимыми для взлома, извлечения или даже уничтожения.
Ранее известная как «Недостаточное ведение журнала и мониторинг», эта категория была расширена и теперь включает в себя больше типов сбоев, включая те, которые сложно проверить, а также те, которые недостаточно хорошо представлены в данных CVE/CVSS.

## 10. Server-Side Request Forgery

Подделка запросов на стороне сервера относится к данным, которые показывают относительно низкую частоту возникновения с охватом тестирования выше среднего и рейтингом потенциала использования и воздействия выше среднего.
 

## Incorrect security configuration

Неправильная конфигурация безопасности. Когда вы, как владелец веб-сайта, не можете установить все необходимые протоколы и средства контроля безопасности для своего веб-сервера, вы делаете его уязвимым для веб-атак. Это неправильная настройка безопасности. Кроме того, вы можете реализовать эти меры безопасности и сделать это с одной или двумя ошибками, которые по-прежнему делают вас уязвимыми.

Неправильную настройку безопасности относительно легко исправить. Во-первых, вам необходимо понять, как работает ваш сайт, выбрать оптимальные меры безопасности для вашего сайта и убедиться, что все реализовано правильно. Используйте надежные пароли администратора и заблокируйте несанкционированный доступ к вашему серверу. Время от времени запускайте сканирование, чтобы обнаружить и устранить любые дыры в безопасности.

## Insecure Direct Object References (IDOR)

Злоумышленнику будет сложно найти на вашем сайте небезопасную прямую ссылку на объект (IDOR). Однако, если они это сделают, они могут легко этим воспользоваться, и последствия могут быть серьезными. Эта уязвимость предполагает несанкционированный доступ с использованием непроверенного пользовательского ввода. Хакеры могут напрямую ссылаться на объекты на вашем веб-сервере.

Первое, что вы можете сделать, — это обнаружить IDOR и заменить ссылки на объекты, используя безопасные хэши или косвенные ссылки на объекты. Затем обеспечьте правильное управление сеансами и всегда проверяйте элементы управления доступом пользователей на уровне объекта.

## Cross-site request forgery

Подделка межсайтового запроса. Когда пользователь посещает веб-сайт, браузер автоматически отправляет токены аутентификации для каждого запроса. Злоумышленник может использовать вредоносную веб-страницу, чтобы изменить взаимодействие между браузером пользователя и посещаемым веб-сайтом. Например, это позволяет им получить доступ к предыдущим файлам cookie аутентификации пользователя для посещенного веб-сайта.

Аутентификация сеанса может помочь вам справиться с подделкой межсайтовых запросов. Этого можно добиться путем выдачи токенов для каждого активного сеанса пользователя, чтобы убедиться, что запросы на сайт отправляет реальный пользователь. Это известно как token-based mitigation (смягчение последствий на основе токенов), и вы можете использовать шаблоны токенов с отслеживанием или без сохранения состояния.

## Используйте стандарт кодирования

Стандарты кодирования, такие как [OWASP](https://www.perforce.com/blog/kw/what-is-owasp-top-10) , [CWE](https://www.perforce.com/blog/kw/what-is-cwe) и [CERT](https://www.perforce.com/blog/kw/what-is-cert), [PA DSS](https://www.perforce.com/blog/kw/what-is-pa-dss), [DISA STIG](https://www.perforce.com/blog/kw/what-is-DISA-STIG), позволяют лучше предотвращать, обнаруживать и устранять уязвимости. Обеспечить соблюдение стандарта кодирования легко, если вы используете инструмент [SAST](https://www.perforce.com/blog/kw/what-is-sast), например [Klocwork](https://www.perforce.com/products/klocwork). Klocwork выявляет дефекты безопасности и уязвимости во время написания кода.

## Другие распространенные уязвимости: Открытые перенаправления

Уязвимость открытого перенаправления — одна из самых простых в использовании и практически не требует опыта взлома. Это недостаток безопасности в приложении, которым можно злоупотребить, чтобы перенаправить пользователей на вредоносный сайт.

Проблема в том, что уязвимые приложения не могут должным образом аутентифицировать URL-адреса, чтобы убедиться, что эти URL-адреса являются частью домена целевой страницы. Вместо этого такие приложения просто перенаправляются на предоставленную страницу независимо от URL-адреса.

Эта уязвимость часто используется для проведения фишинговых атак с целью кражи учетных данных пользователей и обмана принуждения пользователей к совершению платежей.

## Другие распространенные уязвимости: Чрезмерное раскрытие данных

В веб-приложениях мы склонны предоставлять больше данных , чем необходимо, дополнительные свойства объектов, чрезмерную информацию об обработке ошибок и т. д. Это часто делается, когда мы фокусируемся на обеспечении лучшего пользовательского опыта, не принимая во внимание конфиденциальность информации, которую мы раскрываем. Проблема в том, что злоумышленник может злоупотребить этой дополнительной информацией, чтобы получить доступ внутрь сети или перехватить конфиденциальную информацию.

------------------------------------------------------------------------------

# Security

* Public Key Cryptography
* Hashing/Encryption/Encoding
* Hashing Algorithms
* OWASP Top 10

Authentication: Cookie Based, OAuth, Token OAuth, JWT, OpenID, SAML ...

WEB Security Knowledge: MD5 not used, SHA Family, scrypt,bcrypt, CORS, HTTPS,SSL/TLS,Content Security Policy

RBAC, XSS, DDOS, CSRF, CSP, RATE LIMITING, SQL injections  https://backendinterview.ru/ib.html
Broken authentication
В идеале, в проекте должен быть манифест, который регулирует security политику
Про UEBA в безопасности
про Cross Browser Fingerprint
Phishing Detection
DGA, OWASP

# Типы сетевых атак

```
DoS, DDoS, Фишинг, Spoofing, Bruteforce, Переполнение буфера, SQL-иньекции, MITM(Man In The Middle)
Злое ПО: Бэкдоры (Backdoor), Майнеры (Miner), Банкеры (Banker), Шпионские программы (Spyware), Рекламное ПО (Adware)
```


# Что такое security безопасность/уязвимости программы?
# Виды существующих угроз и как защититься от будущих
# Специалисту по защите веб-приложений [OWASP Top Ten](https://owasp.org/www-project-top-ten/) 
# Направление в кибезбезопасности зависит от домена 
  Для WEB и консольных программ - это разные направления
  Для WEB сайтов и WEB банкинга - это разные направления
  Для встраиваемых устройств тоже отличается.

  [Какие инструменты применяют для поиска уязвимостей](https://skillbox.ru/media/code/gayd-po-kiberbezopasnosti-dlya-razrabotchikov-i-nachinayushchikh-spetsialistov/)

[Вещи, которые всегда нужно держать в уме, если вы хотите создать безопасное приложение:](https://tproger.ru/explain/what-programmers-should-know-about-security)

* Не доверяйте входным данным! "out of control of the application"
* Сведите вашу поверхность атаки к минимуму.
* [Используйте моделирование угроз](https://owasp.org/www-community/Threat_Modeling)
* Разделяйте привилегии, чтобы было проще отследить источник проблемы.
* Знайте и помните о переполнении буфера и о том, как от него защититься.

```
Существует несколько замечательных книг и статей на тему того, как сделать приложение безопасным:
    Writing Secure Code 2nd Edition.
    Building Secure Software: How to Avoid Security Problems the Right Way.
    Secure Programming Cookbook.
    Exploiting Software.
    Security Engineering.
    Secure Programming for Linux and Unix HOWTO.


Обучите ваших разработчиков лучшим практикам безопасности:
    Codebashing (платно)
    Security Innovation (платно)
    Security Compass (платно)
    OWASP WebGoat (бесплатно)
```
----------------------------------------------------------------------------------------------------------

[Итак, с чего начать и где научиться охоте за ошибками?](https://www.bugbountyhunting.com/)

[Программисты просто не думают о безопасности, или Зачем в кофеварке Wi-Fi](https://dou.ua/lenta/articles/security-for-developers/)
Существует отдельная дисциплина Threat modeling, которая позволяет прогнозировать угрозы и направления возможной атаки, а также определять ценность данных, которые вы при этом рискуете потерять. Ее можно преподавать не только применительно к IT, но программисты точно должны получать концептуальное представление о ней в базовом комплекте знаний. Также совершенно необходимо, чтобы разработчики знали типичные дырки. Они должны быть в курсе, какими бывают ошибки и как потом за счет них другие люди взламывают системы.


[Web Application Security Basics 101: where to start](https://medium.com/@talhakhalid101/devsecops-basics-where-to-start-aa7babee4ac4)

[С чего начать изучение информационной безопасности](https://codeby.school/blog/informacionnaya-bezopasnost/s-chego-nachat-izuchenie-informacionnoy-bezopasnosti)

[Уязвимости бизнес-логики](https://portswigger.net/web-security/logic-flaws)

[Book: The Tangled Web michal zalewski](https://archive.org/details/tangledwebguidet0000zale)

[Проверьте свое программное обеспечение](https://www.perforce.com/blog/sca/what-static-analysis)