# Ansible to Sophos NG-SIEM

Two Ansible sources reach the Sophos NG-SIEM data collector: ansible-core runs with the `community.general.syslog_json` callback, which sends each task result over syslog, and the AWX or Red Hat Ansible Automation Platform controller's external logging, which sends JSON records over TCP or UDP. These parsers read both.

## Send the task results from ansible-core

1. In Sophos Fusion, set up a data collector that receives syslog over UDP, if you don't have one. The callback sends UDP only.
2. Install the `community.general` collection on the controller and turn the callback on in `ansible.cfg`:

```
[defaults]
callbacks_enabled = community.general.syslog_json
# also log ad hoc commands (ansible, not only ansible-playbook)
bin_ansible_callbacks = True

[callback_syslog_json]
syslog_server = <data collector address>
syslog_port = <port>
syslog_facility = user
```

The messages carry no time, so the event time is when the data collector received them. Results of tasks with `no_log: true` arrive censored, with no command.

## Send the controller's logs from AWX or Ansible Automation Platform

1. In the controller, go to Settings > Logging settings and choose Edit, or set the same values through `/api/v2/settings/logging/`.
2. Set Logging Aggregator to the data collector's address, Logging Aggregator Port to its port, Logging Aggregator Type to `other` and Logging Aggregator Protocol to `TCP` or `UDP`. Each record goes as one JSON line with no syslog header.
3. Keep the loggers `awx`, `activity_stream` and `job_events` in Loggers Sending Data to Log Aggregator Form, set Logging Aggregator Level Threshold to `INFO`, turn on Enable External Logging and save.

The HTTPS protocol sends Basic authentication or a Splunk token, not the bearer token Sophos NG-SIEM HTTP Ingest needs, so use TCP or UDP.

## Add the parsers

| Parser | Events |
| --- | --- |
| `ANSIBLE_SYSLOG_JSON_STANDALONE_MGMT` | syslog_json task results (OK, FAILED, UNREACHABLE, SKIPPED) to Management Event |
| `ANSIBLE_AWX_JSON_PARENT` | Claims the controller's records; anything the children don't take stays generic |
| `ANSIBLE_AWX_JSON_CHILD_AUTH` | Sign-ins, failed sign-ins and sign-outs (logger `awx.api.generics`) to Auth |
| `ANSIBLE_AWX_JSON_CHILD_MGMT` | The activity stream (who created, changed, deleted, associated or launched what) to Management Event |
| `ANSIBLE_AWX_JOB_EVENTS_JSON_CHILD_MGMT` | Each host's task result in a job (job events `runner_on_*`) to Management Event |

Add the parent before its children, with the parent as their parent parser. Use Run Test with your own lines before you turn the parsers on.
