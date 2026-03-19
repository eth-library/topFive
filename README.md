topFive
=======

A CLI tool that reads a web server log file and returns the top N IPs with the most requests within a configurable time window.

Note: It takes the timestamp from the first log entry for the date to analyze.

Also note: There is no Windows version.

And finally: This software was originally developed in 2025 by human brain. Since 2026 AI assists in writing tests and new functions.

## Why it's useful

When your server gets hammered by requests you have to react quickly — without spending time searching for the log file or writing complex greps to see who's doing what.

Just call `topFive` and it will answer with the top five IP addresses with the most requests for the last five minutes. As a first measure you can simply block them.

For further analysis **topFive** creates an output folder and puts a file for each of the top IPs into it. Each file contains the request count and the individual requests with timestamp, method, URL, response code, response time, and User-Agent.

**topFive** is a single binary with no runtime dependencies, uses a bare minimum of resources, and is fast: it parses 100 MB of logs in under 400 milliseconds.

## Usage

In an emergency just call the binary. It runs with these defaults:
- parse `/var/log/httpd/ssl_access_log`
- date layout `"02/Jan/2006:15:04:05 -0700"`
- time window: last 5 minutes
- compute the top 5 IP addresses by request count
- write output to `./output/`:

      xxyyy_aaa.aaa.aaa.aaa.txt
      xxyyy_bbb.bbb.bbb.bbb.txt
      xxxyy_ccc.ccc.ccc.ccc.txt
      xxxyy_ddd.ddd.ddd.ddd.txt
      xxxxy_eee.eee.eee.eee.txt
      response_codes-<timestamp>.txt

  where `xxyyy` is the request count, followed by the IP address.
- write application log to `./logs/<timestamp>.log`
- print the top IPs with request counts to stdout

> **Important:** Your account must have read rights on the log file and write rights on the output and log folders.

## Options

```
-c          custom path to config file (default: /etc/topFive/conf.d/topFive.yml)
-dl         date layout for timestamps in the log file (default: 02/Jan/2006:15:04:05 -0700)
-f          path to the log file to parse (default: /var/log/httpd/ssl_access_log)
-i          filter: only analyze this IP address
-ni         filter: ignore this IP address (prefix match)
-k          aggregate by IP class instead of full IP:
                A  →  x.0.0.0
                B  →  x.x.0.0
                C  →  x.x.x.0
                D  →  x.x.x.x  (default, full IP)
-m          time range in minutes to analyze (default: 5); set to 0 for the whole file
-n          number of top IPs to show (default: 5)
-q          restrict analysis to requests containing this query string
-r          filter: only include this HTTP response code
-nr         filter: exclude this HTTP response code
-t          end time to analyze backwards from, e.g. 15:04 (default: now)
-lt         log type — see supported formats below (default: apache_combined)
-combined   write all top-IP entries into one combined file instead of per-IP files
```

## Supported log formats (`-lt`)

| LogType | Description |
|---------|-------------|
| `apache_combined` | Apache Combined Log Format (default) |
| `apache_common` | Apache Common Log Format (no Referer / User-Agent) |
| `apache_atmire` | Apache Combined with additional Atmire research fields |
| `nginx_combined` | nginx default combined format (identical field positions to Apache Combined) |
| `haproxy_http` | HAProxy 2.x HTTP default log (no syslog prefix, no header captures) |
| `rosetta` | ETHZ Rosetta log format |
| `custom` | Custom format — define field positions via `LogFormat` block in config file |

### HAProxy note

HAProxy timestamps include milliseconds and no timezone offset. Set `DateLayout` accordingly in your config:

```yml
DateLayout: "02/Jan/2006:15:04:05.000"
LogType: haproxy_http
```

If your HAProxy logs include a syslog prefix (`Feb 12 12:14:14 hostname haproxy[pid]:`) or captured header fields (`{...}`), use `LogType: custom` and define the field positions manually.

### Custom log format

Use `LogType: custom` together with a `LogFormat` block to support any space-delimited log format.

Tokenization: quotes are stripped first, then the line is split on spaces.

```yml
LogType: custom
LogFormat:
  IP: 0
  IPFallback: -1       # fallback position when IP token is "-"; -1 to disable
  IPStripPort: false   # strip trailing ":port" from IP token (e.g. for HAProxy)
  TimeStamp: 3         # position of first timestamp token; second part is TimeStamp+1
                       # single-token timestamps (e.g. [ts]) are detected automatically
  Method: 5
  Request: 6
  Code: 8
  RTime:
    Position: 10       # response-time field position; Unit: 0 to disable
    Unit: 1000         # divisor to convert to seconds (e.g. 1000 for ms)
  UserAgent: 11        # first token of User-Agent; -1 to disable
                       # all tokens from this position to EOL are joined
```

## Date layout (`-dl` / `DateLayout`)

Specified according to Go's `time` package. The reference time is:

```
02/Jan/2006:15:04:05 -0700        (Apache / nginx)
02/Jan/2006:15:04:05.000          (HAProxy, millisecond precision)
2006-01-02 15:04:05               (ISO-style, no timezone)
```

## Example call

Analyze `./ssl_access_my.log` with a custom config, from 9:45 to 9:55, ignoring the 192.168.1.x subnet:

```bash
topFive -c conf.d/myConfig.yml -f ./ssl_access_my.log -t 9:55 -m 10 -ni 192.168.1. -dl "2006-01-02 15:04:05"
```

## Configuration example

```yml
DateLayout: "02/Jan/2006:15:04:05 -0700"
OutputFolder: ./output
LogType: apache_combined
DefaultLog2analyze: /var/log/httpd/ssl_access_log

LogConfig:
  LogLevel: Info
  LogFolder: ./logs
```

See `conf.d/` for ready-to-use example configs for Apache, nginx, HAProxy, Rosetta, and custom formats.
