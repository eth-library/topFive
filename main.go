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
// output actually not sorted...

var layout = "02/Jan/2006:15:04:05 -0700"

func get_top_ips(ip_count map[string]int) map[string]int {
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
		top := 5
		if entries < 5 {
			top = entries
		}
		for i := 0; i < top; i++ {
			top_ips[ips[i]] = ip_count[ips[i]]
		}
	}
	return top_ips
}

func last5min_topreq_ips() map[string]int {
	starttime := time.Now().Add(-5 * time.Minute)
	endtime := time.Now()

	IP_rcount := retrieve_records(starttime, endtime)

	top_ips := get_top_ips(IP_rcount)
	return top_ips
}

func retrieve_records(start_time time.Time, end_time time.Time) map[string]int {
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
	for _, record := range records {
		rtime, _ := time.Parse(layout, record[1])
		if start_time.Before(rtime) && end_time.After(rtime) {
			ip_count[record[0]]++
		}
	}
	return ip_count
}

func main() {
	start_time, _ := time.Parse(layout, "11/Oct/2024:07:30:00 +0200")
	end_time, _ := time.Parse(layout, "11/Oct/2024:08:30:00 +0200")
	fmt.Println(start_time, " <> ", end_time)

	IP_rcount := retrieve_records(start_time, end_time)

	top_ips := get_top_ips(IP_rcount)
	for ip, count := range top_ips {
		fmt.Println("IP:", ip, ", (", count, ") requests")
	}
	last5min := last5min_topreq_ips()
	for ip, count := range last5min {
		fmt.Println("IP:", ip, ", (", count, ") requests")
	}
}