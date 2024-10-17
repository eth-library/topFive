topFive
=======

This is a simple program that reads a log file and returns the top five IPs with the most requests.

customized for atmire logs

## Usage
In emergency just call the binary `topFive`, it will run with the following defaults:
- parse the logfile /var/log/httpd/ssl_access_atmire_log
- with the date layout "02/Jan/2006:15:04:05 -0700" for the datestamps within the logfile to analyze,
- from the actual time minus five minutes till now
- compute the top five IP adresses with the most requests during that time range
- write to the folder ./output
- the following six files:
      - xxyyy_aaa.aaa.aaa.aaa.txt
      - xxyyy_bbb.bbb.bbb.bbb.txt
      - xxxyy_ccc.ccc.ccc.ccc.txt
      - xxxyy_ddd.ddd.ddd.ddd.txt
      - xxxxy_eee.eee.eee.eee.txt
      - response_codes.txt
- write a logfile ./logs/yyyymmdd_hhMMss.log
- print out the top five IP adresses with the corresponding request counts

> IMPORTANT: 
> Your Account musst have read rights to the logfile to analyze and access rights to the corresponding folders!

## Options
Customize the call with the following flags:
`-c` to provide a custom path to the config file (default: /etc/topFive/conf.d/examplecfg.yml)
`-d` to provide annother layout for the datestamps within the logfile to analyze (default: 02/Jan/2006:15:04:05 -0700)
`-f` to provide a custom path to the file  to parse (default: /var/log/httpd/ssl_access_atmire_log)
`-k` to summarize the IP class instead of IP addresses where
      A means X.255.255.255 
      B means X.X.255.255 
      C means X.X.X.255 
      defaults to IP adresses: X.X.X.X 
`-m` to provide a custom time range (in minutes, default: 5) to analyze, set to zero (0) to do the whole file 
`-n` to provide the number of top IPs to show (default: 5)
`-t` to provide a custom End-Time (e.g. 15:04) to analyze from backwards (default: time.Now())

### change the date layout (`-d` or DateLayout in the config file)
The data layout is specified according to the time package in go. When specifying the layout it is important to keep the date and time values: 02/Jan/2006:15:04:05 -0700

example call:
```bash
topFive -c conf.d/myConfig.yml -f ./ssl_access_atmire_log -m 5 -t 9:55
```

Note: takes the timestamp from the first log entry for the date to analyze
