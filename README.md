topFive
=======

This is a simple program that reads a log file and returns the top five IPs with the most requests.

customized for atmire logs

## Usage

`topFive -c <config file> -f <log file to analyze> -m <Minutes to parse> -t <timestamp to start from>`

defaults:
```bash
topFive -c conf.d/examplecfg.yml -f /var/log/httpd/ssl_access_atmire_log -m 5 -t 9:55
```

Note: defaults to the actual DSpace http log file and the time range 5 minutes back from now

Note: takes the timestamp from the first log entry for the date
