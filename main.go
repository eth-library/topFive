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
// simply tailored for our one specific case
// generalizations will can be done later

var (
	_, ApplicationName = SeparateFileFromPath(os.Args[0])
	configPath         = flag.String("c", "/etc/topFive/conf.d/topFive.yml", "use -c to provide a custom path to the config file (default: /etc/topFive/conf.d/topFive.yml)")
	config             ApplicationConfig
	LogIt              *slog.Logger
	time2analyze       = flag.Int("m", 5, "use -m to provide a custom time range (in minutes, default: 5) to analyze, set to zero (0) to do the whole file ")
	endtime            = flag.String("t", time.Now().Format("15:04"), "use -t to provide a custom End-Time (e.g. 15:04) to analyze from backwards (default: time.Now())")
	topIPsCount        = flag.Int("n", 5, "use -n to provide the number of top IPs to show (default: 5)")
	IPclass            = flag.String("k", "", "use -k to summarize the IP class instead of IP addresses: A means X.255.255.255 C means X.Y.Z.255 (default to IP adresses: <empty>)")
	log_2_analyze      *Log2Analyze
	file2parse         = flag.String("f", "/var/log/httpd/ssl_access_atmire_log", "use -f to provide a custom path to the file  to parse (default: /var/log/httpd/ssl_access_atmire_log)")
	date_layout        = flag.String("d", "02/Jan/2006:15:04:05 -0700", "use -d to provide annother layout for the datestamps within the logfile to analyze (default: 02/Jan/2006:15:04:05 -0700)")
	ip_adress          = flag.String("i", "", "use -i to provide an IP adress to analyze (default: <empty>)")
	log_type           = flag.String("y", "", "use -y to provide a log type (apache_atmire | rosetta) (default: apache_atmire)")
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

func main() {
	pst := time.Now()

	flag.Parse()

	config.Initialize(configPath)
	// now setup logging
	LogIt = SetupLogging(config.Logcfg)
	fmt.Println("LogLevel is set to " + config.Logcfg.LogLevel)
	fmt.Println("will log to", config.Logcfg.LogFolder)

	log_2_analyze = new(Log2Analyze)
	if FlagIsPassed("d") {
		log_2_analyze.DateLayout = *date_layout
		LogIt.Info("setting DateLayout to " + *date_layout + " instead of DateLayout from config file, because -d is passed")
		fmt.Println("setting DateLayout to " + *date_layout + " instead of DateLayout from config file, because -d is passed")
	} else {
		log_2_analyze.DateLayout = config.DateLayout
	}
	if FlagIsPassed("i") && !FlagIsPassed("m") {
		*time2analyze = 0
		LogIt.Info("setting time2analyze to 0, because an IP adress and no time2analyze is given")
		fmt.Println("setting time2analyze to 0, because an IP adress and no time2analyze is given")
		fmt.Println("  which means: will analyze the whole file")
	}
	if FlagIsPassed("y") || config.LogType == "" {
		config.LogType = *log_type
		LogIt.Info("setting LogType to " + *log_type)
		fmt.Println("setting LogType to " + *log_type)
	}
	fmt.Println("output is written to", config.OutputFolder)
	// start working
	if FlagIsPassed("f") || config.DefaultFile2analyze == "" {
		log_2_analyze.FileName = *file2parse
		LogIt.Info("setting FileName to " + *file2parse)
		fmt.Println("setting FileName to " + *file2parse)
	}

	log_2_analyze.RetrieveEntries(*endtime, *time2analyze)

	top_ips, code_count := log_2_analyze.GetTopIPs()
	log_2_analyze.WriteOutputFiles(top_ips, code_count)
	LogIt.Info("Top IPs in between" + fmt.Sprintf("%v", log_2_analyze.StartTime) + " and " + fmt.Sprintf("%v", log_2_analyze.EndTime))
	fmt.Println("Top IPs in between", log_2_analyze.StartTime, " and ", log_2_analyze.EndTime)
	fmt.Println("\tIP\t\tCount")
	print_sorted(top_ips)
	fmt.Printf("finished in %v\n", time.Since(pst))
}
