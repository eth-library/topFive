package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

type LogEntry struct {
	IP        string
	TimeStamp string
	Request   string
	Code      string
	RTime     string
}

// func to parse whole file
func retrieve_records(file2parse string, timestamps ...time.Time) []LogEntry {
	// retrieves the records from the log file within a time range or of the whole file
	// if no timestamps are given
	file, err := os.Open(file2parse)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file) // scan the contents of a file and print line by line
	for scanner.Scan() {
		line := scanner.Text()
		// das Folgende ist nicht universell nutzbar: Ich entferne die Anführungszeichen
		// und ersetze sie durch Leerzeichen und splitte die Zeile dann an den Leerzeichen
		parts := strings.Split(strings.Replace(line, "\"", "", -1), " ")
		if len(timestamps) == 0 || line_matches(parts[4], timestamps) {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading from file:", err) // print error if scanning is not done properly
	}

	if len(timestamps) == 0 {
		for _, record := range records {
			ip_count[record[0]]++
		}
		start_time, end_time := timestamps[0], timestamps[1]
		for _, record := range records {
			rtime, _ := time.Parse(config.Layout, record[1])
			if start_time.Before(rtime) && end_time.After(rtime) {
			}
		}
	}
}

func line_matches(line string, timestamps []time.Time) bool {
	return true
}

func count_requests(records []LogEntry) map[string]int {
	// counts the requests per ip
	ip_count := make(map[string]int)
	for _, record := range records {
		ip_count[record.IP]++
	}
	return ip_count
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
