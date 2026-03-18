// Package main implements topFive, a CLI tool that analyses web server log files
// (Apache, Rosetta, logfmt) and reports the top N IP addresses by request count
// within a configurable time window.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"time"
)

// Command-line flags and global state used throughout the application.
var (
	_, ApplicationName = SeparateFileFromPath(os.Args[0])
	configPath         = flag.String("c", "/etc/topFive/conf.d/topFive.yml", "use -c to provide a custom path to the config file")
	config             ApplicationConfig
	LogIt              *slog.Logger
	timeRange          = flag.Int("m", 5, "use -m to provide a custom time range in minutes to analyze, set to zero (0) to do the whole file ")
	endtime            = flag.String("t", time.Now().Format("15:04"), "use -t to provide a custom End-Time (e.g. 15:04) to analyze from backwards")
	topIPsCount        = flag.Int("n", 5, "use -n to provide the number of top IPs to show")
	IPclass            = flag.String("k", "D", "use -k to summarize the IP class instead of IP addresses: A means X.255.255.255 C means X.Y.Z.255")
	log2Analyze        *Log2Analyze
	file2parse         = flag.String("f", "/var/log/httpd/ssl_access_log", "use -f to provide a custom path to the file  to parse")
	dateLayout         = flag.String("dl", "02/Jan/2006:15:04:05 -0700", "use -dl to provide annother layout for the datestamps within the logfile to analyze")
	date2analyze       = flag.String("d", time.Now().Format("2006-01-02"), "use -d to provide the date to analyze")
	ipAddress          = flag.String("i", "", "use -i to provide an IP adress to analyze")
	notIP              = flag.String("ni", "", "use -ni to provide an IP adress to ignore in analysis")
	queryString        = flag.String("q", "", "use -q to provide a string to query the logfile for")
	logType            = flag.String("lt", "apache", "use -lt to provide a log type (apache_atmire | rosetta | apache | logfmt)")
	logFormat          = flag.String("lf", "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"", "use -lf to provide a log format (according to apache log strings)")
	responseCode       = flag.Int("r", 0, "use -r to provide a response code to filter for")
	noResponseCode     = flag.Int("nr", 0, "use -nr to provide a response code to ignore in analysis")
	combinedFile       = flag.Bool("combined", false, "use -combined to write all top-IPs into one file")
)

// sortByRcount returns a formatted string listing the entries of ipRcount
// sorted in descending order by request count.
func sortByRcount(ipRcount map[string]int) string {
	var output string
	// maps are not ordered, so we need to sort the map by the request count
	entries := len(ipRcount)
	if entries > 0 {
		// first step: get all the keys from the map into a slice, that can be sorted
		ips := make([]string, 0, entries)
		for ip := range ipRcount {
			ips = append(ips, ip)
		}
		// second step: sort the slice by the request count
		sort.SliceStable(ips, func(i, j int) bool {
			return ipRcount[ips[i]] > ipRcount[ips[j]]
		})
		// third step: iterate over the sorted slice and print the ip and the request count
		for _, ip := range ips {
			output += "\t" + ip + "\t: " + fmt.Sprintf("%v", ipRcount[ip]) + "\n"
		}
	}
	return output
}

func main() {
	pst := time.Now()

	flag.Parse()

	config.Initialize(configPath)
	// now setup logging
	LogIt = SetupLogging(config.Logcfg)
	fmt.Println("LogLevel is set to " + config.Logcfg.LogLevel)
	fmt.Println("will log to", config.Logcfg.LogFolder)

	log2Analyze = new(Log2Analyze)
	if FlagIsPassed("dl") {
		log2Analyze.DateLayout = *dateLayout
		LogIt.Info("setting DateLayout to " + *dateLayout + " instead of DateLayout from config file, because -l is passed")
		fmt.Println("setting DateLayout to " + *dateLayout + " instead of DateLayout from config file, because -l is passed")
	} else {
		log2Analyze.DateLayout = config.DateLayout
	}
	if FlagIsPassed("i") && !FlagIsPassed("m") {
		*timeRange = 0
		LogIt.Info("setting timeRange to 0, because an IP adress and no timeRange is given")
		fmt.Println("setting timeRange to 0, because an IP adress and no timeRange is given")
		fmt.Println("  which means: will analyze the whole file")
	}
	if FlagIsPassed("ni") {
		LogIt.Info("ip to ignore is set to " + fmt.Sprint(*notIP))
		fmt.Println("ip to ignore is set to " + fmt.Sprint(*notIP))
	}
	if FlagIsPassed("lt") || config.LogType == "" {
		config.LogType = *logType
		LogIt.Info("setting LogType to " + *logType)
		fmt.Println("setting LogType to " + *logType)
	}
	if FlagIsPassed("l") || config.LogFormat == "" {
		config.LogFormat = *logFormat
		LogIt.Info("setting log format to " + *logFormat)
		fmt.Println("setting log format to " + *logFormat)
	}
	if FlagIsPassed("d") {
		log2Analyze.Date2analyze = *date2analyze
	} else {
		log2Analyze.Date2analyze = time.Now().Format("2006-01-02")
	}
	LogIt.Info("setting date to analyze to " + log2Analyze.Date2analyze)
	fmt.Println("setting date to analyze to " + log2Analyze.Date2analyze)

	if FlagIsPassed("q") {
		LogIt.Info("query string is set to " + *queryString)
		fmt.Println("query string is set to " + *queryString)
		log2Analyze.QueryString = *queryString
	}

	if FlagIsPassed("r") {
		LogIt.Info("response code to filter for is set to " + fmt.Sprint(*responseCode))
		fmt.Println("response code to filter for is set to " + fmt.Sprint(*responseCode))
	}

	if FlagIsPassed("nr") {
		LogIt.Info("response code to ignore is set to " + fmt.Sprint(*noResponseCode))
		fmt.Println("response code to ignore is set to " + fmt.Sprint(*noResponseCode))
	}

	fmt.Println("output is written to", config.OutputFolder)
	// start working
	if FlagIsPassed("f") || config.DefaultFile2analyze == "" {
		log2Analyze.FileName = *file2parse
		LogIt.Info("setting FileName to " + *file2parse)
		fmt.Println("setting FileName to " + *file2parse)
	} else {
		log2Analyze.FileName = config.DefaultFile2analyze
	}

	log2Analyze.RetrieveEntries(*endtime, *timeRange)

	topIPs, codeCount := log2Analyze.GetTopIPs()

	log2Analyze.WriteOutputFiles(topIPs, codeCount)
	// print output
	infos := make(map[string]string)
	var timestamps []string
	infos["Total requests"] = fmt.Sprintf("%v", log2Analyze.EntryCount)
	if *timeRange != 0 {
		timestamps = append(timestamps, log2Analyze.StartTime.Format("2006-01-02 15:04"))
		timestamps = append(timestamps, log2Analyze.EndTime.Format("2006-01-02 15:04"))
		infos["Requests per second"] = fmt.Sprintf("%v", log2Analyze.EntryCount/(*timeRange*60))
	}
	if log2Analyze.QueryString != "" {
		infos["query string"] = log2Analyze.QueryString
	}

	header := BuildOutputHeader(log2Analyze.FileName, time.Now().Local().Format("20060102_150405"), timestamps, infos)
	fmt.Println(header)
	LogIt.Info(header)
	sortedIPs := sortByRcount(topIPs)
	fmt.Println("")
	fmt.Println("\tTop IPs\t\t: count")
	fmt.Println("\t------------------------------")
	fmt.Println(sortedIPs)
	LogIt.Info(sortedIPs)
	fmt.Printf("finished in %v\n", time.Since(pst))
}
