package main

import (
	"flag"
	"fmt"
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
	// config             ApplicationConfig
	// LogIt              *slog.Logger
	file2parse   = flag.String("f", "testdata/access-2024-10-11.log", "use -f to provide a custom path to the file  to parse (default: testdata/access-2024-10-11.log)")
	time2analyze = flag.Int("m", 5, "use -t to provide a custom time range (in minutes) to analyze (default: 5)")
	time2gofrom  = flag.String("t", time.Now().Format("15:04"), "use -t to provide a custom time range (in minutes) to analyze (default: time.Now())")
)

func get_top_ips(ip_count map[string]int) map[string]int {
	// returns the five ip addresses with the highest request count
	// to prevent it from crashing, when the given map ip_count, we check the length
	// of the map and if it is empty, we return an empty map
	// if the map is not empty, we sort the map by the request count and return the top 5 or less
	top_ips := make(map[string]int)
	entries := len(ip_count)
	if entries > 0 {
		// build a slice of the keys of the map, so we can sort it to gett the top 5
		ips := make([]string, 0, entries)
		for ip := range ip_count {
			ips = append(ips, ip)
		}
		// sort the slice by the request count
		sort.SliceStable(ips, func(i, j int) bool {
			return ip_count[ips[i]] > ip_count[ips[j]]
		})
		if entries > 5 {
			entries = 5
		}
		// get the top 5 or less, if there are less than 5 entries
		// be aware, that the resulting map (top_ips) is not ordered!
		for i := 0; i < entries; i++ {
			top_ips[ips[i]] = ip_count[ips[i]]
		}
	}
	return top_ips
}

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
		}
	}
}

func create_time_range() (time.Time, time.Time) {
	// creates a time range to analyze the log file
	// the range is defined by the time2analyze flag
	endtimestring := fmt.Sprintf("%s %s", time.Now().Format("2006-01-02"), *time2gofrom)
	endtime, _ := time.Parse("2006-01-02 15:04", endtimestring)
	starttime := endtime.Add(time.Duration(-*time2analyze) * time.Minute)
	return starttime, endtime
}

func main() {
	flag.Parse()

	starttime, endtime := create_time_range()

	if isFlagPassed("w") {
		records := retrieve_records(file2parse)
	} else {
		records := retrieve_records(file2parse, starttime, endtime)
	}
	IP_rcount := retrieve_records(starttime, endtime)

	top_overall := full_file_topreq_ips()
	fmt.Println("Top 5 IPs in the whole file:")
	print_sorted(top_overall)
	top_ips := get_top_ips(IP_rcount)
	fmt.Println("Top 5 IPs in between", starttime, " and ", endtime)
	print_sorted(top_ips)
	last5min := last5min_topreq_ips()
	fmt.Println("Top 5 IPs in the last 5 minutes:")
	print_sorted(last5min)
}
