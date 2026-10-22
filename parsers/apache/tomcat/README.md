# Apache Tomcat to Sophos NG-SIEM

Apache Tomcat writes its access log and its own logs to files only, so a log forwarder on the server sends them to the Sophos NG-SIEM data collector. These parsers read the access log in the default pattern or as JSON, and Tomcat's own log lines for Manager deployments, LockOutRealm lockouts and shutdown commands.

## Send the logs

1. In Sophos Fusion, set up a data collector that receives syslog, if you don't have one.
2. Keep the access log valve's default pattern in `conf/server.xml`, or switch to the JSON valve (Tomcat 9.0.74, 10.1.8 or later):

```
<Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
       prefix="localhost_access_log" suffix=".txt" pattern="%h %l %u %t &quot;%r&quot; %s %b" />
<Valve className="org.apache.catalina.valves.JsonAccessLogValve" directory="logs"
       prefix="localhost_access_log" suffix=".json" pattern="common" />
```

   With the `combined` pattern, the library's nginx and Apache access log entry reads the lines instead.
3. Keep `java.util.logging.ConsoleHandler.formatter` and the file handlers on `org.apache.juli.OneLineFormatter`, the default in `conf/logging.properties`. Run Tomcat with `-Duser.timezone=UTC`: these lines carry the JVM's local time with no zone and are read as UTC.
4. Forward `logs/localhost_access_log.*`, `logs/catalina.*.log` and `logs/manager.*.log` (or `catalina.out`) to the data collector line by line, for example with rsyslog's `imfile` and a tag such as `tomcat-access` and `tomcat`. A stack trace's later lines stay unparsed.

## Add the parsers

| Parser | Events |
| --- | --- |
| `TOMCAT_ACCESS_STANDALONE_HTTP` | Access log lines (default pattern, or JSON) to HTTP, with the client, user, method, path, query, status and bytes |
| `TOMCAT_JULI_PARENT` | Claims Tomcat's own log lines; anything the children don't take stays generic |
| `TOMCAT_JULI_CHILD_AUTH` | Sign-ins refused because LockOutRealm locked the user, to Auth |
| `TOMCAT_JULI_CHILD_MGMT` | Deployments, undeployments, reloads and WAR uploads (Manager application and HostConfig), and shutdown commands, to Management Event |

Add the parent before its children, with the parent as their parent parser. Use Run Test with your own lines before you turn the parsers on.

Tomcat logs no other failed sign-in by default: Manager sign-in failures show as `401` responses in the access log, and the access log's `%u` names the Manager user, which the Manager's own lines don't.
