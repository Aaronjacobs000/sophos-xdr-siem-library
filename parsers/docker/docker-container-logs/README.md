# Docker container logs to Sophos NG-SIEM

Docker sends each container's output (stdout and stderr) to the logging driver you choose. These parsers read the syslog driver's lines and the json-file driver's lines once they reach the Sophos NG-SIEM data collector, and set the Docker host, the container and the time. A container's output is its application's own text, so the events stay in the generic schema; use a parser for that application's format to normalize it.

## Send the logs

1. In Sophos Fusion, set up a data collector that receives syslog, if you don't have one.
2. Either send the containers' output with the syslog driver, in `/etc/docker/daemon.json` or per container with `--log-driver` and `--log-opt`:

```
{
  "log-driver": "syslog",
  "log-opts": {
    "syslog-address": "tcp://<data collector address>:<port>",
    "syslog-format": "rfc5424",
    "tag": "{{.Name}}/{{.ID}}"
  }
}
```

   Keep the container ID at the end of the tag (the default tag is `{{.ID}}` alone): the parser finds Docker lines by it. Use `rfc5424` or `rfc5424micro`, whose times carry the offset; the default and `rfc3164` formats send dockerd's local time with no year or zone, read as UTC. A daemon-wide change applies to containers created after the restart.
3. Or keep the default json-file driver and forward `/var/lib/docker/containers/*/*-json.log` with a file forwarder, one line at a time. Set the `tag` log option (for example `{{.Name}}/{{.ID}}`) so each line carries the container in `attrs.tag`; without it the line doesn't say which container wrote it.

## Add the parsers

| Parser | Lines |
| --- | --- |
| `DOCKER_SYSLOG_STANDALONE_GENERIC` | Syslog driver lines in the default, `rfc3164`, `rfc5424` and `rfc5424micro` formats |
| `DOCKER_JSONFILE_STANDALONE_GENERIC` | json-file driver lines (`{"log":...,"stream":...,"time":...}`), with or without the forwarder's syslog header |

Each sets `sensor_type` Docker, the Docker host as `host_id` where the line carries it, the tag (the container) as `sensor_id`, and the event time. Use Run Test with your own lines before you turn the parsers on.
