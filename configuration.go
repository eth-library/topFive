package main

import (
	"fmt"
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

// ApplicationConfig holds the top-level application settings, typically loaded
// from a YAML configuration file.
type ApplicationConfig struct {
	DateLayout          string    `yaml:"DateLayout"`
	OutputFolder        string    `yaml:"OutputFolder"`
	DefaultFile2analyze string    `yaml:"DefaultLog2analyze"`
	LogType             string    `yaml:"LogType"`
	LogFormat           string    `yaml:"LogFormat"`
	Logcfg              LogConfig `yaml:"LogConfig"`
}

// LogConfig contains settings for the application's own log output.
type LogConfig struct {
	LogLevel  string `yaml:"LogLevel"`
	LogFolder string `yaml:"LogFolder"`
}

// ToDo: standardize logfile layout according to https://httpd.apache.org/docs/2.4/mod/mod_log_config.html#formats

// Initialize populates the configuration by first setting defaults and then
// overlaying values from the YAML file at configPath (if it exists).
// It calls CheckConfig to validate and normalise the resulting config.
func (config *ApplicationConfig) Initialize(configPath *string) {
	// 1. set defaults
	config.setDefaults()
	// 2. read config and run with defaults if not found
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
		LogType:      "apache",
		LogFormat:    "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"",
		Logcfg: LogConfig{
			LogLevel:  "INFO",
			LogFolder: "./logs/",
		},
	}
}

// CheckConfig normalises directory paths (ensuring trailing slashes) and
// verifies that the required directories exist, prompting for creation if not.
func (c *ApplicationConfig) CheckConfig() {
	// TODO: hier könnte noch ein DateLayoutCheck rein
	checknaddtrailingslash(&c.Logcfg.LogFolder)
	// check if the log folder exists
	if !CheckIfDir(c.Logcfg.LogFolder) {
		ToBeCreated(c.Logcfg.LogFolder)
	}
	checknaddtrailingslash(&c.OutputFolder)
	// check if the output folder exists
	if !CheckIfDir(c.OutputFolder) {
		ToBeCreated(c.OutputFolder)
	}
}

// File2Parse represents a file that is to be parsed/analyzed.
type File2Parse struct {
	FileName string
}
