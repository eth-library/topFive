package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"time"
)

func get_top_ip(records [][]string, start_times string, end_times string) (string, int) {
	datetime_layout := "02/Jan/2006:15:04:05 Z0700"
	start_time, _ := time.Parse(datetime_layout, start_times)
	end_time, _ := time.Parse(datetime_layout, end_times)
	fmt.Println(start_time, " <> ", end_time)
	ip_count := make(map[string]int)
	for _, record := range records {
		rtimestamp, _ := time.Parse(datetime_layout, record[1])
		if start_time.Before(rtimestamp) && end_time.After(rtimestamp) {
			fmt.Println(rtimestamp)
			ip_count[record[0]]++
		}
	}
	max_ip := ""
	max_count := 0
	for ip, count := range ip_count {
		if count > max_count {
			max_count = count
			max_ip = ip
		}
	}
	return max_ip, max_count
}

func main() {
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

	top_ip, req_count := get_top_ip(records, "11/Oct/2024:07:30:00 +0200", "11/Oct/2024:08:30:00 +0200")
	fmt.Println("Top IP:", top_ip, ", (", req_count, ") requests")
}
