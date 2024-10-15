package main

import (
	"fmt"
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

// configuration structures
// ========================

type ApplicationConfig struct {
	DateLayout   string    `yaml:"DateLayout"`
	OutputFolder string    `yaml:"OutputFolder"`
	Logcfg       LogConfig `yaml:"LogConfig"`
}

type LogConfig struct {
	LogLevel  string `yaml:"LogLevel"`
	LogFolder string `yaml:"LogFolder"`
}

func (config *ApplicationConfig) Initialize(configPath *string) {
	// 1. set defaults
	config.setDefaults()
	// 2. read config
	file := GetCleanPath(*configPath)
	yamlFile, err := os.ReadFile(file)
	if err != nil {
		log.Fatalln("critical", "No config found at "+file+", will stop now.", err)
	}

	if err = yaml.Unmarshal(yamlFile, &config); err != nil {
		log.Fatalln("ERROR parsing config", fmt.Sprint(err))
	}

	config.CheckConfig()
}

func (config *ApplicationConfig) setDefaults() {
	*config = ApplicationConfig{
		OutputFolder: "./output/",
		Logcfg: LogConfig{
			LogLevel:  "INFO",
			LogFolder: "./logs/",
		},
	}
}

func (c *ApplicationConfig) CheckConfig() {
	// TODO: hier muss dringend noch ein DateLayoutChack rein
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

// further stuctures and functions
// ================================

type File2Parse struct {
	FileName string
}
