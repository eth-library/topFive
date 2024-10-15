topFive
=======

This is a simple program that reads a log file and returns the top five IPs with the most requests.

customized for atmire logs

## Usage

Just call the binary `./topFive`

Customize the call with the following flags:
`-c` to provide a custom path to the config file (default: ./conf.d/examplecfg.yml)
`-f` to provide a custom path to the file  to parse (default: /var/log/httpd/ssl_access_atmire_log)
`-k` to summarize the IP class instead of IP addresses where
      A means X.255.255.255 
      B means X.X.255.255 
      C means X.X.X.255 
      defaults to IP adresses: X.X.X.X 
`-m` to provide a custom time range (in minutes, default: 5) to analyze, set to zero (0) to do the whole file 
`-n` to provide the number of top IPs to show (default: 5)
`-t` to provide a custom End-Time (e.g. 15:04) to analyze from backwards (default: time.Now())


example call:
```bash
topFive -c conf.d/examplecfg.yml -f /var/log/httpd/ssl_access_atmire_log -m 5 -t 9:55
```

Note: defaults to the actual DSpace http log file and the time range 5 minutes back from now

Note: takes the timestamp from the first log entry for the date to analyze
