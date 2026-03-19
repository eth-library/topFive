package main

import (
	"fmt"
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

// RTimeConfig describes where and how to read the response-time field.
// Position is the index in the flat-tokenized line (after quote removal and
// space-split). Unit is the divisor to convert the stored value to seconds
// (e.g. 1000 when the log stores milliseconds).
// A Unit of 0 means no RTime field is present for this format.
type RTimeConfig struct {
	Position int `yaml:"Position"`
	Unit     int `yaml:"Unit"`
}

// LogFormatConfig describes the field positions in a flat-tokenized log line.
// Tokenization: strings.Replace(line, `"`, "", -1) followed by strings.Split(" ").
//
// TimeStamp refers to the first of two consecutive tokens that together form
// the timestamp (e.g. "[17/Mar/2026:06:30:01" and "+0100]"); the parser
// automatically reads TimeStamp and TimeStamp+1 and strips the brackets.
// Single-token timestamps (e.g. HAProxy "[06/Feb/2009:12:14:14.655]") are
// detected automatically: if the first token (after "[" removal) already
// ends with "]", the second token is not read.
//
// IPFallback is the token index used when the primary IP token is "-";
// set to -1 to disable fallback.
//
// IPStripPort removes a trailing ":port" from the IP token (e.g. HAProxy
// logs "client_ip:client_port" as a single token).
//
// UserAgent is the index of the first token of the User-Agent string.
// Because User-Agent values can contain spaces (and the flat tokenizer splits
// on every space after quote removal), the parser joins all tokens from
// UserAgent to the end of the line. Set to -1 to disable UA parsing.
type LogFormatConfig struct {
	IP          int         `yaml:"IP"`
	IPFallback  int         `yaml:"IPFallback"`
	IPStripPort bool        `yaml:"IPStripPort"`
	TimeStamp   int         `yaml:"TimeStamp"`
	Method      int         `yaml:"Method"`
	Request     int         `yaml:"Request"`
	Code        int         `yaml:"Code"`
	RTime       RTimeConfig `yaml:"RTime"`
	UserAgent   int         `yaml:"UserAgent"`
}

// ApplicationConfig holds the top-level application settings, typically loaded
// from a YAML configuration file.
type ApplicationConfig struct {
	DateLayout          string          `yaml:"DateLayout"`
	OutputFolder        string          `yaml:"OutputFolder"`
	DefaultFile2analyze string          `yaml:"DefaultLog2analyze"`
	LogType             string          `yaml:"LogType"`
	LogFormat           LogFormatConfig `yaml:"LogFormat"`
	Logcfg              LogConfig       `yaml:"LogConfig"`
}

// LogConfig contains settings for the application's own log output.
type LogConfig struct {
	LogLevel  string `yaml:"LogLevel"`
	LogFolder string `yaml:"LogFolder"`
}

// apacheLogFormat returns the LogFormatConfig for Apache Combined / Apache-Atmire
// logs, using flat tokenization (quote removal + space split).
//
//	[0]=IP [1]=- [2]=user [3]=[ts1 [4]=ts2] [5]=method [6]=request [7]=protocol [8]=code …
func apacheLogFormat() LogFormatConfig {
	return LogFormatConfig{
		IP:         0,
		IPFallback: -1,
		TimeStamp:  3,
		Method:     5,
		Request:    6,
		Code:       8,
		RTime:      RTimeConfig{Position: 0, Unit: 0},
		UserAgent:  11,
	}
}

// apacheCommonLogFormat returns the LogFormatConfig for the Apache Common log
// format (no Referer or User-Agent fields). Field positions are identical to
// Apache Combined; only UserAgent is disabled.
//
//	[0]=IP [1]=- [2]=user [3]=[ts1 [4]=ts2] [5]=method [6]=request [7]=protocol [8]=code …
func apacheCommonLogFormat() LogFormatConfig {
	return LogFormatConfig{
		IP:         0,
		IPFallback: -1,
		TimeStamp:  3,
		Method:     5,
		Request:    6,
		Code:       8,
		RTime:      RTimeConfig{Position: 0, Unit: 0},
		UserAgent:  -1,
	}
}

// haproxyHTTPLogFormat returns the LogFormatConfig for the HAProxy HTTP default
// log format (HAProxy 2.x, no syslog prefix, no header captures).
// DateLayout must be set to "02/Jan/2006:15:04:05.000" in the config file.
//
//	[0]=IP:port [1]=[ts] [2]=frontend [3]=backend/server [4]=timers
//	[5]=code [6]=bytes [7]=termination [8]=connections [9]=queue [10]=method [11]=request …
func haproxyHTTPLogFormat() LogFormatConfig {
	return LogFormatConfig{
		IP:          0,
		IPFallback:  -1,
		IPStripPort: true,
		TimeStamp:   1,
		Method:      10,
		Request:     11,
		Code:        5,
		RTime:       RTimeConfig{Position: 0, Unit: 0},
		UserAgent:   -1,
	}
}

// rosettaLogFormat returns the LogFormatConfig for the Rosetta log format,
// using flat tokenization (quote removal + space split).
//
//	[0]=clientIP [1]=forwardedIP [2]=- [3]=- [4]=[ts1 [5]=ts2] [6]=method [7]=request
//	[8]=protocol [9]=code [10]=bytes [11]=rtimeMs …
func rosettaLogFormat() LogFormatConfig {
	return LogFormatConfig{
		IP:         1,
		IPFallback: 0,
		TimeStamp:  4,
		Method:     6,
		Request:    7,
		Code:       9,
		RTime:      RTimeConfig{Position: 11, Unit: 1000},
		UserAgent:  16,
	}
}

// applyLogTypePreset overwrites LogFormat with the predefined field positions
// for the given LogType. For "custom" (or any unknown type) the LogFormat
// from the config file is used unchanged.
func (c *ApplicationConfig) applyLogTypePreset() {
	switch c.LogType {
	case "apache_combined", "apache_atmire", "nginx_combined", "logfmt":
		c.LogFormat = apacheLogFormat()
	case "apache_common":
		c.LogFormat = apacheCommonLogFormat()
	case "haproxy_http":
		c.LogFormat = haproxyHTTPLogFormat()
	case "rosetta":
		c.LogFormat = rosettaLogFormat()
	// "custom" and unknown types: leave LogFormat as configured
	}
}

// Initialize populates the configuration by first setting defaults and then
// overlaying values from the YAML file at configPath (if it exists).
// It calls CheckConfig to validate and normalise the resulting config.
func (config *ApplicationConfig) Initialize(configPath *string) {
	config.setDefaults()
	file := GetCleanPath(*configPath)
	yamlFile, err := os.ReadFile(file)
	if err != nil {
		fmt.Println("could not read config from " + file + ", will run with defaults.")
	} else {
		if err = yaml.Unmarshal(yamlFile, &config); err != nil {
			log.Fatalln("ERROR parsing config", fmt.Sprint(err))
		}
	}
	config.CheckConfig()
}

// setDefaults populates config with sensible default values.
func (config *ApplicationConfig) setDefaults() {
	*config = ApplicationConfig{
		DateLayout:   "02/Jan/2006:15:04:05 -0700",
		OutputFolder: "./output/",
		LogType:      "apache_combined",
		LogFormat:    apacheLogFormat(),
		Logcfg: LogConfig{
			LogLevel:  "INFO",
			LogFolder: "./logs/",
		},
	}
}

// CheckConfig normalises directory paths (ensuring trailing slashes),
// applies the log-type preset, and verifies that required directories exist.
func (c *ApplicationConfig) CheckConfig() {
	c.applyLogTypePreset()
	checknaddtrailingslash(&c.Logcfg.LogFolder)
	if !CheckIfDir(c.Logcfg.LogFolder) {
		ToBeCreated(c.Logcfg.LogFolder)
	}
	checknaddtrailingslash(&c.OutputFolder)
	if !CheckIfDir(c.OutputFolder) {
		ToBeCreated(c.OutputFolder)
	}
}

// File2Parse represents a file that is to be parsed/analyzed.
type File2Parse struct {
	FileName string
}
