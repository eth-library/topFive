package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"
)

type LogEntry struct {
	IP        string
	TimeStamp string
	Method    string
	Request   string
	Code      string
	RTime     string
}

type Log2Analyze struct {
	FileName   string
	DateLayout string
	Entries    []LogEntry
}

func (e LogEntry) Between(start, end time.Time) bool {
	// checks if the LogEntry is between the start and end time
	t, _ := time.Parse(log_2_analyze.DateLayout, e.TimeStamp)
	passt := t.After(start) && t.Before(end)

	LogIt.Debug(start.Format(log_2_analyze.DateLayout) + " > " + e.TimeStamp + " > " + end.Format(log_2_analyze.DateLayout) + " :: " + fmt.Sprintf("%v", passt))
	return passt
}

func (l Log2Analyze) GetTopIPs() map[string]int {
	// returns the five ip addresses with the highest request count within the last 5 minutes
	ip_count := make(map[string]int)
	for _, record := range l.Entries {
		ip_count[record.IP]++
	}
	return get_top_ips(ip_count)
}

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

func (l *Log2Analyze) RetrieveEntries(timestamps ...time.Time) {
	// retrieves the records from the log file within a time range or of the whole file
	// if no timestamps are given
	file, err := os.Open(l.FileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file) // scan the contents of a file and print line by line
	c := 0
	cl := 0
	for scanner.Scan() {
		line := scanner.Text()
		cl++
		// das Folgende ist nicht universell nutzbar: Ich entferne die Anführungszeichen
		// und ersetze sie durch Leerzeichen und splitte die Zeile dann an den Leerzeichen
		entry := create_entry(line)
		if len(timestamps) == 0 || entry.Between(timestamps[0], timestamps[1]) {
			l.Entries = append(l.Entries, entry)
			c++
		}
	}
	LogIt.Info("checked " + fmt.Sprintf("%d", cl) + " lines")
	LogIt.Info("found Entries within timerange: " + fmt.Sprintf("%v", len(l.Entries)))
	LogIt.Debug(" counter says: " + fmt.Sprintf("%d", c))

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading from file:", err) // print error if scanning is not done properly
	}
}

func create_entry(line string) LogEntry {
	// creates a LogEntry from a line
	parts := strings.Split(strings.Replace(line, "\"", "", -1), " ")
	timestamp := strings.Replace(parts[3], "[", "", 1) + " " + strings.Replace(parts[4], "]", "", 1)
	return LogEntry{
		IP:        parts[0],
		TimeStamp: timestamp,
		Method:    parts[5],
		Request:   parts[6],
		Code:      parts[8],
	}
}

func count_requests(records []LogEntry) map[string]int {
	// counts the requests per ip
	ip_count := make(map[string]int)
	for _, record := range records {
		ip_count[record.IP]++
	}
	return ip_count
}

// func last5min_topreq_ips() map[string]int {
// 	// returns the five ip addresses with the highest request count within the last 5 minutes
// 	starttime := time.Now().Add(-5 * time.Minute)
// 	endtime := time.Now()
//
// 	IP_rcount := retrieve_records(starttime, endtime)
//
// 	top_ips := get_top_ips(IP_rcount)
// 	return top_ips
// }
//
// func full_file_topreq_ips() map[string]int {
// 	// returns the five ip addresses with the highest request count in the whole file
// 	IP_rcount := retrieve_records()
//
// 	top_ips := get_top_ips(IP_rcount)
// 	return top_ips
// }

// if len(timestamps) == 0 {
// 	for _, record := range records {
// 		ip_count[record[0]]++
// 	}
// 	start_time, end_time := timestamps[0], timestamps[1]
// 	for _, record := range records {
// 		rtime, _ := time.Parse(config.Layout, record[1])
// 		if start_time.Before(rtime) && end_time.After(rtime) {
// 		}
// 	}
