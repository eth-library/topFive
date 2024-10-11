package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"sort"
	"time"
)

// Notes
// options:
// -f <filename> - the name of the log file to watch
// -l <layout> - the layout of the datetime in the log file
// tail -F -n 1 ssl_access_atmire_log | awk '{sub(/\[/,"",$4);sub(/\]/,"",$5);print $1","$4,$5}'

var layout = "02/Jan/2006:15:04:05 -0700"

func get_top_ips(ip_count map[string]int) map[string]int {
	// returns the five ip addresses with the highest request count
	// to prevent it from crashing, when the given map ip_count, we check the length
	// of the map and if it is empty, we return an empty map
	// if the map is not empty, we sort the map by the request count and return the top 5 or less
	top_ips := make(map[string]int)
	entries := len(ip_count)
	if entries > 0 {
		ips := make([]string, 0, entries)
		for ip := range ip_count {
			ips = append(ips, ip)
		}
		sort.SliceStable(ips, func(i, j int) bool {
			return ip_count[ips[i]] > ip_count[ips[j]]
		})
		if entries > 5 {
			entries = 5
		}
		for i := 0; i < entries; i++ {
			top_ips[ips[i]] = ip_count[ips[i]]
		}
	}
	return top_ips
}

func last5min_topreq_ips() map[string]int {
	// returns the five ip addresses with the highest request count within the last 5 minutes
	starttime := time.Now().Add(-5 * time.Minute)
	endtime := time.Now()

	IP_rcount := retrieve_records(starttime, endtime)

	top_ips := get_top_ips(IP_rcount)
	return top_ips
}

func full_file_topreq_ips() map[string]int {
	// returns the five ip addresses with the highest request count in the whole file
	IP_rcount := retrieve_records()

	top_ips := get_top_ips(IP_rcount)
	return top_ips
}

func retrieve_records(timestamps ...time.Time) map[string]int {
	// retrieves the records from the log file within a time range or of the whole file
	file, err := os.Open("testdata/access-2024-10-11.log")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Println("Error reading records", err)
	}
	ip_count := make(map[string]int)
	if len(timestamps) == 0 {
		for _, record := range records {
			ip_count[record[0]]++
		}
		return ip_count
	} else {
		start_time, end_time := timestamps[0], timestamps[1]
		for _, record := range records {
			rtime, _ := time.Parse(layout, record[1])
			if start_time.Before(rtime) && end_time.After(rtime) {
				ip_count[record[0]]++
			}
		}
	}
	return ip_count
}

func print_sorted(IP_rcount map[string]int) {
	// maps are not ordered, so we need to sort the map by the request count
	entries := len(IP_rcount)
	if entries > 0 {
		ips := make([]string, 0, entries)
		for ip := range IP_rcount {
			ips = append(ips, ip)
		}
		sort.SliceStable(ips, func(i, j int) bool {
			return IP_rcount[ips[i]] > IP_rcount[ips[j]]
		})
		for _, ip := range ips {
			fmt.Println("\t", ip, "\t", IP_rcount[ip])
		}
	}
}

func main() {
	start_time, _ := time.Parse(layout, "11/Oct/2024:07:30:00 +0200")
	end_time, _ := time.Parse(layout, "11/Oct/2024:08:30:00 +0200")
	fmt.Println(start_time, " <> ", end_time)

	IP_rcount := retrieve_records(start_time, end_time)

	top_overall := full_file_topreq_ips()
	fmt.Println("Top 5 IPs in the whole file:")
	print_sorted(top_overall)
	top_ips := get_top_ips(IP_rcount)
	fmt.Println("Top 5 IPs in between", start_time, " and ", end_time)
	print_sorted(top_ips)
	last5min := last5min_topreq_ips()
	fmt.Println("Top 5 IPs in the last 5 minutes:")
	print_sorted(last5min)
}
