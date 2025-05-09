topFive
=======

This is a simple program that reads a log file and returns the top five IPs with the most requests.
It is customized for atmire httpd logs.

Note: It takes the timestamp from the first log entry for the date to analyze

## why it's useful:
When your server get's hammered by requests you have to react quickly without spending the time with searching for the logfile and having to write complex greps to see, who's doing whta on your machine.

Instead just call `topFive` and it will answer with the top five IP addresses with the most requests for the last five minutes. As a first aid you could simply block them.

But there's more: for further analysis **topFive** will create an output folder and put a file for each of the top five IP addresses into it. Each file contains the request count and the requests with the timestamp, the request type, the request itself and the response code.

**topFive** is a simple binary with no dependecies, uses a bare minimum of ressources when executed, so it won't stress your machine while it's under attack, and **topFive** is fast. It will parse 100MB in under 400 milliseconds.

## Usage
In emergency just call the binary `topFive`, it will run with the following defaults:
- parse the logfile `/var/log/httpd/ssl_access_atmire_log`
- with the date layout `"02/Jan/2006:15:04:05 -0700"` for the datestamps within the logfile to analyze,
- from the actual time minus five minutes till now
- compute the top five IP adresses with the most requests during that time range
- write to the folder `./output`
- the following six files:

      - xxyyy_aaa.aaa.aaa.aaa.txt
      - xxyyy_bbb.bbb.bbb.bbb.txt
      - xxxyy_ccc.ccc.ccc.ccc.txt
      - xxxyy_ddd.ddd.ddd.ddd.txt
      - xxxxy_eee.eee.eee.eee.txt
      - response_codes.txt
    where xxyyy is the request count, followed by an underscore and the requesting IP address.
- write a logfile `./logs/YYYYMMDD_hhmmss.log`
- print out the top five IP adresses with the corresponding request counts

> IMPORTANT: 
> Your Account musst have read rights to the logfile to analyze and access rights to the corresponding folders!


## Options
Customize the call with the following flags:
```
`-c`        to provide a custom path to the config file (default: /etc/topFive/conf.d/examplecfg.yml)
`-l`        to provide annother layout for the datestamps within the logfile to analyze (default: 02/Jan/2006:15:04:05 -0700)
`-f`        to provide a custom path to the file  to parse (default: /var/log/httpd/ssl_access_atmire_log)
`-i`        to provide an IP adress to analyze (default: <empty>)
`-k`        to summarize the IP class instead of IP addresses where
                  A means X.255.255.255 
                  B means X.X.255.255 
                  C means X.X.X.255 
                  defaults to IP adresses: X.X.X.X 
`-m`        to provide a custom time range (in minutes, default: 5) to analyze, set to zero (0) to do the whole file 
`-n`        to provide the number of top IPs to show (default: 5)
`-q`        to provide a query string to restrict the analysis to (default: <empty>)
`-r`        to provide a response code to filter for
`-nr`       to provide a response code to ignore in analysis
`-t`        to provide a custom End-Time (e.g. 15:04) to analyze from backwards (default: time.Now())
`-y`        to provide a log type (apache_atmire | rosetta) (default: apache_atmire)"
`-combined` to write all top-IPs into one file
```

### change the date layout (`-l` or DateLayout in the config file)
The data layout is specified according to the time package in go. When specifying the layout it is important to keep the date and time values: 02/Jan/2006:15:04:05 -0700

## example call:
Call `topFive` with a custom config at `conf.d/myConfig.yml` to analyze the file `./ssl_access_my.log.` Analyze **t**ill `9:55` *back* 10 minutes (time range from 9:45 **t**ill 9:55). The Datestamps within the file `./ssl_access_my.log` will be in the format `YYYY-MM-DD hh:mm:ss` without a timezone:

```bash
topFive -c conf.d/myConfig.yml -f ./ssl_access_my.log -t 9:55 -m 10 -l "2006-01-02 15:04:05"
```

## configuration example

```yml
DateLayout: "02/Jan/2006:15:04:05 -0700"
OutputFolder: ./output
LogType: apache_atmire
DefaultLog2analyze: /var/log/httpd/ssl_access_atmire_log

LogConfig:
  LogLevel: Debug
  LogFolder: ./logs
```
