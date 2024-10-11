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
	Layout  string    `yaml:"Layout"`
	TempDir string    `yaml:"TempDir"`
	Logcfg  LogConfig `yaml:"LogConfig"`
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
}

func (config *ApplicationConfig) setDefaults() {
	*config = ApplicationConfig{
		TempDir: "./tmp",
		Logcfg: LogConfig{
			LogLevel:  "INFO",
			LogFolder: "./logs",
		},
	}
}
