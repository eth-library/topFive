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
	Class     string
	TimeStamp time.Time
	Method    string
	Request   string
	Code      string
	RTime     string
}

type Log2Analyze struct {
	FileName   string
	DateLayout string
	StartTime  time.Time
	EndTime    time.Time
	Entries    []LogEntry
}

func (l *Log2Analyze) RetrieveEntries(endtime string, timerange int) {
	// retrieves the records from the log file within a time range or of the whole file
	// if no timerange is given
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
		if l.StartTime.IsZero() {
			LogIt.Debug("l.StartTime is zero, setting Start and End Time")
			l.StartTime, l.EndTime = create_time_range(endtime, timerange, entry.TimeStamp)
			LogIt.Debug("Start Time: " + l.StartTime.Format(log_2_analyze.DateLayout))
			LogIt.Debug("End Time: " + l.EndTime.Format(log_2_analyze.DateLayout))
		}
		if timerange == 0 || entry.Between(l.StartTime, l.EndTime) {
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

func (l Log2Analyze) GetTopIPs() map[string]int {
	// returns the five ip addresses with the highest request count within the last 5 minutes
	ip_count := make(map[string]int)
	for _, record := range l.Entries {
		ip_count[record.Class]++
	}

	// to prevent it from crashing, when the given map ip_count, we check the length
	// of the map and if it is empty, we return an empty map
	// if the map is not empty, we sort the map by the request count and return the top 5 or less
	top_ips := make(map[string]int)
	entries := len(ip_count)
	if entries > *topIPsCount {
		entries = *topIPsCount
	}
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
		// get the top 5 or less, if there are less than 5 entries
		// be aware, that the resulting map (top_ips) is not ordered!
		for i := 0; i < entries; i++ {
			top_ips[ips[i]] = ip_count[ips[i]]
		}
	}
	return top_ips
}

func (l Log2Analyze) WriteOutputFiles(top_ips map[string]int) {
	for ip, count := range top_ips {
		file, err := os.Create(config.OutputFolder + fmt.Sprintf("%05d", count) + "_" + ip + ".txt")
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		file.WriteString(ip + "\t" + fmt.Sprintf("%v", count) + "\n")
		for _, record := range l.Entries {
			if record.Class == ip {
				file.WriteString(record.TimeStamp.Format(l.DateLayout) + "\t" + record.IP + "\t" + record.Method + "\t" + record.Request + "\t" + record.Code + "\n")
			}
		}
	}
}

func (e LogEntry) Between(start, end time.Time) bool {
	// checks if the LogEntry is between the start and end time
	passt := e.TimeStamp.After(start) && e.TimeStamp.Before(end)

	// the following line produces heavy debug output
	// LogIt.Debug(start.Format(log_2_analyze.DateLayout) + " > " + e.TimeStamp.Format(log_2_analyze.DateLayout) + " > " + end.Format(log_2_analyze.DateLayout) + " :: " + fmt.Sprintf("%v", passt))
	return passt
}

func create_entry(line string) LogEntry {
	// creates a LogEntry from a line
	parts := strings.Split(strings.Replace(line, "\"", "", -1), " ")
	timestring := strings.Replace(parts[3], "[", "", 1) + " " + strings.Replace(parts[4], "]", "", 1)
	timestamp, err := time.Parse(log_2_analyze.DateLayout, timestring)
	if err != nil {
		LogIt.Error("Error parsing timestamp: " + timestring + " with layout " + log_2_analyze.DateLayout)
		LogIt.Error("Error parsing timestamp: " + err.Error())
	}
	// switch to get the IP class
	var ip_class string
	ip_parts := strings.Split(parts[0], ".")
	switch *IPclass {
	case "A":
		ip_class = ip_parts[0]
	case "B":
		ip_class = ip_parts[0] + "." + ip_parts[1]
	case "C":
		ip_class = ip_parts[0] + "." + ip_parts[1] + "." + ip_parts[2]
	default:
		ip_class = parts[0]
	}
	return LogEntry{
		IP:        parts[0],
		Class:     ip_class,
		TimeStamp: timestamp,
		Method:    parts[5],
		Request:   parts[6],
		Code:      parts[8],
	}
}

func create_time_range(endtimestring string, timerange int, firstTimestamp time.Time) (time.Time, time.Time) {
	// creates a time range to analyze the log file
	// the range is defined by the time2analyze flag
	LogIt.Debug("got End Time String: " + endtimestring)
	LogIt.Debug("got Time Range: " + fmt.Sprintf("%d", timerange))
	LogIt.Debug("got First Timestamp: " + firstTimestamp.Format(log_2_analyze.DateLayout))
	endtimestring = fmt.Sprintf("%s %s:00 %s", firstTimestamp.Format("2006-01-02"), endtimestring, time.Now().Local().Format("Z0700"))
	LogIt.Debug("End Time String: " + endtimestring)
	endtime, _ := time.Parse("2006-01-02 15:04:05 -0700", endtimestring)
	LogIt.Debug("created End Time: " + endtime.Format(log_2_analyze.DateLayout))
	starttime := endtime.Add(time.Duration(-timerange) * time.Minute)
	LogIt.Debug("created Start Time( - " + fmt.Sprintf("%d", timerange) + "): " + starttime.Format(log_2_analyze.DateLayout))
	return starttime, endtime
}

func count_requests(records []LogEntry) map[string]int {
	// counts the requests per ip
	ip_count := make(map[string]int)
	for _, record := range records {
		ip_count[record.IP]++
	}
	return ip_count
}
