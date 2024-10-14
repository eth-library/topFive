package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"time"
)

// Notes
// options:
// -f <filename> - the name of the log file to watch
// -l <layout> - the layout of the datetime in the log file
// tail -F -n 1 ssl_access_atmire_log | awk '{sub(/\[/,"",$4);sub(/\]/,"",$5);print $1","$4,$5}'
// no configs etc - simply tailored for our one specific case
// Verallgemeinerungen später

var (
	_, ApplicationName = SeparateFileFromPath(os.Args[0])
	// configPath         = flag.String("c", "./conf.d/examplecfg.yml", "use -c to provide a custom path to the config file (default: ./conf.d/examplecfg.yml)")
	config        ApplicationConfig
	LogIt         *slog.Logger
	time2analyze  = flag.Int("m", 5, "use -t to provide a custom time range (in minutes) to analyze (default: 5)")
	time2gofrom   = flag.String("t", time.Now().Format("15:04"), "use -t to provide a custom time range (in minutes) to analyze (default: time.Now())")
	log_2_analyze *Log2Analyze
	file2parse    = flag.String("f", "/Users/sven/temp/rc-logs/prod-logs10/ssl_access_atmire_log", "use -f to provide a custom path to the file  to parse (default: /Users/sven/temp/rc-logs/prod-logs10/ssl_access_atmire_log)")
)

func print_sorted(IP_rcount map[string]int) {
	// maps are not ordered, so we need to sort the map by the request count
	entries := len(IP_rcount)
	if entries > 0 {
		// first step: get all the keys from the map into a slice, that can be sorted
		ips := make([]string, 0, entries)
		for ip := range IP_rcount {
			ips = append(ips, ip)
		}
		// second step: sort the slice by the request count
		sort.SliceStable(ips, func(i, j int) bool {
			return IP_rcount[ips[i]] > IP_rcount[ips[j]]
		})
		// third step: iterate over the sorted slice and print the ip and the request count
		for _, ip := range ips {
			fmt.Println("\t", ip, "\t", IP_rcount[ip])
			LogIt.Info("  " + fmt.Sprintf("%v", ip) + " : " + fmt.Sprintf("%v", IP_rcount[ip]))
		}
	}
}

func create_time_range() (time.Time, time.Time) {
	// creates a time range to analyze the log file
	// the range is defined by the time2analyze flag
	endtimestring := fmt.Sprintf("%s %s:00 %s", time.Now().Format("2006-01-02"), *time2gofrom, time.Now().Local().Format("Z0700"))
	endtime, _ := time.Parse("2006-01-02 15:04:05 -0700", endtimestring)
	starttime := endtime.Add(time.Duration(-*time2analyze) * time.Minute)
	return starttime, endtime
}

func main() {
	flag.Parse()

	cfgpath := "conf.d/examplecfg.yml"
	config.Initialize(&cfgpath)
	// now setup logging
	LogIt = SetupLogging(config.Logcfg)
	fmt.Println("LogLevel is set to " + config.Logcfg.LogLevel)

	starttime, endtime := create_time_range()
	// var log_2_analyze Log2Analyze
	log_2_analyze = new(Log2Analyze)
	log_2_analyze.DateLayout = "02/Jan/2006:15:04:05 Z0700"
	log_2_analyze.FileName = *file2parse
	// var records Log
	if isFlagPassed("w") {
		fmt.Println("Going to parse the whole file")
		log_2_analyze.RetrieveEntries()
	} else {
		fmt.Println("Going to parse the file from", starttime, " to ", endtime)
		LogIt.Info("Going to parse the file from" + fmt.Sprintf("%v", starttime) + " to " + fmt.Sprintf("%v", endtime))
		log_2_analyze.RetrieveEntries(starttime, endtime)
	}

	top_ips := log_2_analyze.GetTopIPs()
	fmt.Println("Top 5 IPs in between", starttime, " and ", endtime)
	LogIt.Info("Top 5 IPs in between" + fmt.Sprintf("%v", starttime) + " and " + fmt.Sprintf("%v", endtime))
	print_sorted(top_ips)
}
