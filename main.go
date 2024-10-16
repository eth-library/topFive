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
	configPath         = flag.String("c", "./conf.d/examplecfg.yml", "use -c to provide a custom path to the config file (default: ./conf.d/examplecfg.yml)")
	config             ApplicationConfig
	LogIt              *slog.Logger
	time2analyze       = flag.Int("m", 5, "use -m to provide a custom time range (in minutes, default: 5) to analyze, set to zero (0) to do the whole file ")
	endtime            = flag.String("t", time.Now().Format("15:04"), "use -t to provide a custom End-Time (e.g. 15:04) to analyze from backwards (default: time.Now())")
	topIPsCount        = flag.Int("n", 5, "use -n to provide the number of top IPs to show (default: 5)")
	IPclass            = flag.String("k", "", "use -k to summarize the IP class instead of IP addresses: A means X.255.255.255 C means X.Y.Z.255 (default to IP adresses: <empty>)")
	log_2_analyze      *Log2Analyze
	file2parse         = flag.String("f", "/var/log/httpd/ssl_access_atmire_log", "use -f to provide a custom path to the file  to parse (default: /var/log/httpd/ssl_access_atmire_log)")
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
	flag.Parse()

	config.Initialize(configPath)
	// now setup logging
	LogIt = SetupLogging(config.Logcfg)
	fmt.Println("LogLevel is set to " + config.Logcfg.LogLevel)

	log_2_analyze = new(Log2Analyze)
	log_2_analyze.DateLayout = config.DateLayout
	log_2_analyze.FileName = *file2parse

	log_2_analyze.RetrieveEntries(*endtime, *time2analyze)

	top_ips, code_count := log_2_analyze.GetTopIPs()
	log_2_analyze.WriteOutputFiles(top_ips, code_count)
	LogIt.Info("Top IPs in between" + fmt.Sprintf("%v", log_2_analyze.StartTime) + " and " + fmt.Sprintf("%v", log_2_analyze.EndTime))
	fmt.Println("Top IPs in between", log_2_analyze.StartTime, " and ", log_2_analyze.EndTime)
	fmt.Println("\tIP\t\tCount")
	print_sorted(top_ips)
}
