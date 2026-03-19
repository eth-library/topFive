package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// LogEntry represents a single parsed line from a web server log file.
type LogEntry struct {
	IP        string
	Class     string
	TimeStamp time.Time
	Method    string
	Request   string
	Code      int
	RTime     string
	UserAgent string
}

// Log2Analyze holds the state for a log analysis session, including the parsed
// entries, time window, and metadata about the file being analysed.
type Log2Analyze struct {
	FileName     string
	DateLayout   string
	StartTime    time.Time
	EndTime      time.Time
	Date2analyze string
	QueryString  string
	Entries      []LogEntry
	EntryCount   int
}

// safeGet returns parts[i] or "" when i is out of range.
func safeGet(parts []string, i int) string {
	if i >= 0 && i < len(parts) {
		return parts[i]
	}
	return ""
}

// ipToClass derives the aggregation class from a raw IP string according to
// the -k flag (A/B/C/D). Non-IPv4 addresses are returned unchanged.
func ipToClass(ip string) string {
	p := strings.Split(ip, ".")
	if len(p) != 4 {
		return ip
	}
	switch *IPclass {
	case "A":
		return p[0]
	case "B":
		return p[0] + "." + p[1]
	case "C":
		return p[0] + "." + p[1] + "." + p[2]
	default: // "D" and anything else
		return ip
	}
}

// parseGeneric tokenizes a log line (quote removal + space split) and extracts
// all fields using the positions defined in config.LogFormat.
//
// Tokenization: strings.Replace(line, `"`, "", -1)  →  strings.Split(" ")
//
// The timestamp always spans two consecutive tokens (lf.TimeStamp and
// lf.TimeStamp+1); square brackets are stripped before parsing.
func parseGeneric(line string) (string, string, time.Time, string, string, int, string, string) {
	lf := config.LogFormat
	parts := strings.Split(strings.Replace(line, `"`, "", -1), " ")

	// IP with optional fallback and optional port stripping
	ip := safeGet(parts, lf.IP)
	if ip == "-" && lf.IPFallback >= 0 {
		ip = safeGet(parts, lf.IPFallback)
	}
	if lf.IPStripPort {
		if i := strings.LastIndex(ip, ":"); i > 0 {
			ip = ip[:i]
		}
	}

	// TimeStamp: normally two consecutive tokens ("[ts1" + "ts2]"), brackets
	// stripped. Single-token timestamps (e.g. "[06/Feb/2009:12:14:14.655]")
	// are detected automatically: if ts1 already ends with "]" after "[" removal
	// the second token is not used.
	ts1 := strings.Replace(safeGet(parts, lf.TimeStamp), "[", "", 1)
	var timestamp time.Time
	var err error
	var tsStr string
	if strings.HasSuffix(ts1, "]") {
		tsStr = strings.TrimSuffix(ts1, "]")
	} else {
		ts2 := strings.Replace(safeGet(parts, lf.TimeStamp+1), "]", "", 1)
		tsStr = ts1 + " " + ts2
	}
	timestamp, err = time.Parse(log2Analyze.DateLayout, tsStr)
	if err != nil {
		LogIt.Error("Error parsing timestamp: " + tsStr + " with layout " + log2Analyze.DateLayout)
		LogIt.Error("Error: " + err.Error())
	}

	// Method and Request
	method := safeGet(parts, lf.Method)
	request := safeGet(parts, lf.Request)

	// Response code
	codeStr := safeGet(parts, lf.Code)
	code, err := strconv.Atoi(codeStr)
	if err != nil {
		LogIt.Error("Error parsing code (maybe hacking?): " + codeStr)
		LogIt.Error(line)
		code = 0
	}

	// Response time (only when Unit > 0)
	rtime := ""
	if lf.RTime.Unit > 0 {
		rtime = safeGet(parts, lf.RTime.Position)
	}

	// User-Agent: join all tokens from lf.UserAgent to end (UA can contain spaces)
	userAgent := ""
	if lf.UserAgent >= 0 && lf.UserAgent < len(parts) {
		userAgent = strings.Join(parts[lf.UserAgent:], " ")
	}

	class := ipToClass(ip)
	return ip, class, timestamp, method, request, code, rtime, userAgent
}

// RetrieveEntries reads the log file and populates l.Entries with all log
// entries that match the current filter criteria (time range, IP, response code,
// query string). If timerange is 0 the entire file is scanned.
func (l *Log2Analyze) RetrieveEntries(endtime string, timerange int) {
	file, err := os.Open(l.FileName)
	if err != nil {
		LogIt.Debug("Error opening file: " + l.FileName)
		fmt.Println("Error opening file: " + l.FileName)
		log.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			LogIt.Debug("Error closing file: " + l.FileName)
		}
	}()

	scanner := bufio.NewScanner(file)
	c := 0
	cl := 0
	for scanner.Scan() {
		line := scanner.Text()
		cl++
		entry := createEntry(line)
		// StartTime is zero if this is the first entry
		if l.StartTime.IsZero() {
			LogIt.Debug("l.StartTime is zero, setting Start and End Time")
			l.StartTime, l.EndTime = createTimeRange(endtime, timerange, l.Date2analyze)
			LogIt.Debug("Start Time: " + l.StartTime.Format(log2Analyze.DateLayout))
			LogIt.Debug("End Time: " + l.EndTime.Format(log2Analyze.DateLayout))
		}
		// check to avoid crash
		entryIP := ""
		if len(entry.IP) < len(*ipAddress) {
			entryIP = entry.IP
		} else {
			entryIP = entry.IP[0:len(*ipAddress)]
		}
		entryNIP := ""
		if len(entry.IP) < len(*notIP) {
			entryNIP = entry.IP
		} else {
			entryNIP = entry.IP[0:len(*notIP)]
		}
		if (timerange == 0 || entry.Between(l.StartTime, l.EndTime)) &&
			(*ipAddress == "" || entryIP == *ipAddress) &&
			(*notIP == "" || entryNIP != *notIP) &&
			(*responseCode == 0 || entry.Code == *responseCode) &&
			(*noResponseCode == 0 || entry.Code != *noResponseCode) {
			if strings.Contains(entry.Request, l.QueryString) || l.QueryString == "" {
				l.Entries = append(l.Entries, entry)
				c++
			}
		}
		if timerange == 0 {
			l.EndTime = entry.TimeStamp
		}
	}
	l.EntryCount = len(l.Entries)
	LogIt.Info("checked " + fmt.Sprintf("%d", cl) + " lines")
	LogIt.Info("found Entries within timerange: " + fmt.Sprintf("%v", l.EntryCount))
	LogIt.Debug(" counter says: " + fmt.Sprintf("%d", c))

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading from file:", err)
	}
}

// GetTopIPs returns the top N IP classes by request count along with a map of
// HTTP status code frequencies. N is controlled by the -n flag (topIPsCount).
func (l Log2Analyze) GetTopIPs() (map[string]int, map[int]int) {
	ipCount := make(map[string]int)
	codeCount := make(map[int]int)
	for _, record := range l.Entries {
		ipCount[record.Class]++
		codeCount[record.Code]++
	}

	topIPs := make(map[string]int)
	entries := len(ipCount)
	if entries > *topIPsCount && *topIPsCount > 0 {
		entries = *topIPsCount
	}
	if entries > 0 {
		ips := make([]string, 0, entries)
		for ip := range ipCount {
			ips = append(ips, ip)
		}
		sort.SliceStable(ips, func(i, j int) bool {
			return ipCount[ips[i]] > ipCount[ips[j]]
		})
		for i := 0; i < entries; i++ {
			topIPs[ips[i]] = ipCount[ips[i]]
		}
	}
	return topIPs, codeCount
}

// WriteOutputFiles writes the analysis results to the configured output folder.
// Depending on the -combined flag it writes either one file per top IP or a
// single combined file. A response-code summary file is always written.
func (l Log2Analyze) WriteOutputFiles(topIPs map[string]int, codeCounts map[int]int) {
	if *topIPsCount > 0 {
		if *combinedFile {
			cfile, err := os.Create(config.OutputFolder + "combined-" + time.Now().Local().Format("20060102_150405") + ".txt")
			if err != nil {
				log.Fatal(err)
			}
			defer cfile.Close()
			infos := make(map[string]string)
			var timestamps []string
			infos["Total requests"] = fmt.Sprintf("%v", l.EntryCount)
			if *timeRange != 0 {
				timestamps = append(timestamps, l.StartTime.Format("2006-01-02 15:04"))
				timestamps = append(timestamps, l.EndTime.Format("2006-01-02 15:04"))
				infos["Requests per second"] = fmt.Sprintf("%v", l.EntryCount/(*timeRange*60))
			}
			if l.QueryString != "" {
				infos["query string"] = l.QueryString
			}

			header := BuildOutputHeader(l.FileName, time.Now().Local().Format("20060102_150405"), timestamps, infos)
			cfile.WriteString(header)

			if *topIPsCount < 31 {
				cfile.WriteString("\n\tTop IPs\t\t: count")
				cfile.WriteString("\n\t------------------------------\n")
				cfile.WriteString(sortByRcount(topIPs))
			}

			cfile.WriteString("\n")
			for ip, count := range topIPs {
				cfile.WriteString("\n")
				cfile.WriteString(ip + "\t" + "=> " + fmt.Sprintf("%v", count) + " requests\n")
				cfile.WriteString("==================================================================\n")
				for _, record := range l.Entries {
					if record.Class == ip {
						cfile.WriteString(record.TimeStamp.Format(l.DateLayout) + "\t" + record.IP + "\t" + record.Method + "\t" + record.Request + "\t" + fmt.Sprintf("%d", record.Code) + "\t" + record.RTime + "\t" + record.UserAgent + "\n")
					}
				}
			}
		} else {
			for ip, count := range topIPs {
				file, err := os.Create(config.OutputFolder + fmt.Sprintf("%05d", count) + "_" + ip + ".txt")
				if err != nil {
					log.Fatal(err)
				}
				defer file.Close()
				file.WriteString(ip + "\t" + fmt.Sprintf("%v", count) + "\n")
				for _, record := range l.Entries {
					if record.Class == ip {
						file.WriteString(record.TimeStamp.Format(l.DateLayout) + "\t" + record.IP + "\t" + record.Method + "\t" + record.Request + "\t" + fmt.Sprintf("%d", record.Code) + "\t" + record.RTime + "\t" + record.UserAgent + "\n")
					}
				}
			}
		}
	} else {
		file, err := os.Create(config.OutputFolder + "ip-list.txt")
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		ips := make([]string, 0, len(topIPs))
		for ip := range topIPs {
			ips = append(ips, ip)
		}
		sort.SliceStable(ips, func(i, j int) bool {
			return topIPs[ips[i]] > topIPs[ips[j]]
		})
		for _, ip := range ips {
			file.WriteString(ip + "\t" + fmt.Sprintf("%v", topIPs[ip]) + "\n")
		}
	}
	file, err := os.Create(config.OutputFolder + "response_codes-" + time.Now().Local().Format("20060102_150405") + ".txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	file.WriteString("Code\tCount\n====\t=======\n")
	entries := len(codeCounts)
	if entries > 0 {
		codes := make([]int, 0, entries)
		for code := range codeCounts {
			codes = append(codes, code)
		}
		sort.SliceStable(codes, func(i, j int) bool {
			return codeCounts[codes[i]] > codeCounts[codes[j]]
		})
		for _, c := range codes {
			file.WriteString(fmt.Sprintf("%d\t%d", c, codeCounts[c]) + "\n")
		}
	}
}

// GetTopLongRequests returns the top N IP classes by maximum response time.
// The raw RTime string is divided by config.LogFormat.RTime.Unit to convert
// to seconds. N is controlled by the -n flag (topIPsCount).
func (l Log2Analyze) GetTopLongRequests() map[string]float64 {
	unit := float64(config.LogFormat.RTime.Unit)
	if unit == 0 {
		unit = 1000
	}
	rtimeMax := make(map[string]float64)
	for _, entry := range l.Entries {
		if entry.RTime == "" {
			continue
		}
		rt, err := strconv.ParseFloat(entry.RTime, 64)
		if err != nil {
			continue
		}
		rt = rt / unit
		if rt > rtimeMax[entry.Class] {
			rtimeMax[entry.Class] = rt
		}
	}

	topRequests := make(map[string]float64)
	entries := len(rtimeMax)
	if entries > *topIPsCount && *topIPsCount > 0 {
		entries = *topIPsCount
	}
	if entries > 0 {
		ips := make([]string, 0, len(rtimeMax))
		for ip := range rtimeMax {
			ips = append(ips, ip)
		}
		sort.SliceStable(ips, func(i, j int) bool {
			return rtimeMax[ips[i]] > rtimeMax[ips[j]]
		})
		for i := 0; i < entries; i++ {
			topRequests[ips[i]] = rtimeMax[ips[i]]
		}
	}
	return topRequests
}

// WriteResponseTimeFile writes a file containing all log entries whose IP class
// appears in topLongRequests. The file is written to config.OutputFolder.
func (l Log2Analyze) WriteResponseTimeFile(topLongRequests map[string]float64) {
	file, err := os.Create(config.OutputFolder + "response_times-" + time.Now().Local().Format("20060102_150405") + ".txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	for ip, rtime := range topLongRequests {
		file.WriteString(fmt.Sprintf("%s\t=> %.1f s\n", ip, rtime))
		file.WriteString("==================================================================\n")
		for _, entry := range l.Entries {
			if entry.Class == ip {
				file.WriteString(entry.TimeStamp.Format(l.DateLayout) + "\t" + entry.IP + "\t" + entry.Method + "\t" + entry.Request + "\t" + fmt.Sprintf("%d", entry.Code) + "\t" + entry.RTime + "\t" + entry.UserAgent + "\n")
			}
		}
		file.WriteString("\n")
	}
}

// Between reports whether e.TimeStamp falls strictly between start and end
// (exclusive on both boundaries).
func (e LogEntry) Between(start, end time.Time) bool {
	return e.TimeStamp.After(start) && e.TimeStamp.Before(end)
}

// createEntry parses a log line and returns a LogEntry using the generic parser.
func createEntry(line string) LogEntry {
	ip, class, timestamp, method, request, code, rtime, userAgent := parseGeneric(line)
	return LogEntry{
		IP:        ip,
		Class:     class,
		TimeStamp: timestamp,
		Method:    method,
		Request:   request,
		Code:      code,
		RTime:     rtime,
		UserAgent: userAgent,
	}
}

// createTimeRange builds a start/end time window. The window ends at
// endtimestring on date2analyze and spans timerange minutes backwards.
// If timerange is 0 the start time is the zero value.
func createTimeRange(endtimestring string, timerange int, date2analyze string) (time.Time, time.Time) {
	LogIt.Debug("got End Time String: " + endtimestring)
	LogIt.Debug("got Time Range: " + fmt.Sprintf("%d", timerange))
	endtimestring = fmt.Sprintf("%s %s:00 %s", date2analyze, endtimestring, time.Now().Local().Format("Z0700"))
	LogIt.Debug("End Time String: " + endtimestring)
	endtime, _ := time.Parse("2006-01-02 15:04:05 -0700", endtimestring)
	LogIt.Debug("created End Time: " + endtime.Format(log2Analyze.DateLayout))

	var starttime time.Time
	if timerange > 0 {
		starttime = endtime.Add(time.Duration(-timerange) * time.Minute)
	}
	LogIt.Debug("created Start Time( - " + fmt.Sprintf("%d", timerange) + "): " + starttime.Format(log2Analyze.DateLayout))
	return starttime, endtime
}
