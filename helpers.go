package main

import (
	"bufio"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// FlagIsPassed reports whether the flag with the given name was explicitly set
// on the command line. It inspects the default flag.CommandLine.
func FlagIsPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// StringInSlice reports whether name is present in sl.
func StringInSlice(name string, sl []string) bool {
	return slices.Contains(sl, name)
}

// GetStringSliceElementIndex returns the index of value in slice, or -1 if not found.
func GetStringSliceElementIndex(slice []string, value string) int {
	for i, v := range slice {
		if v == value {
			return i
		}
	}
	return -1
}

// GetCleanPath returns the cleaned version of path using filepath.Clean.
func GetCleanPath(path string) string {
	return filepath.Clean(path)
}

// checknaddtrailingslash appends a trailing "/" to *path if one is not already present.
func checknaddtrailingslash(path *string) {
	if !strings.HasSuffix(*path, "/") {
		*path = *path + "/"
	}
}

// CheckIfDir reports whether path exists and is a directory.
func CheckIfDir(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		fmt.Println("DEBUG", err)
		return false
	} else {
		if fileInfo.IsDir() {
			return true
		} else {
			// TODO: catch error if it is a file and not a directory
			return false
		}
	}
}

// ToBeCreated prompts the user interactively to create the missing directory at path.
func ToBeCreated(path string) {
	fmt.Println("the folder " + path + " is missing")
	var anlegen string
	yes := []string{"j", "J", "y", "Y"}
	fmt.Print("shall I create it? (y|n) [n]: ")
	fmt.Scanln(&anlegen)
	if StringInSlice(anlegen, yes) {
		if err := os.MkdirAll(path, 0750); err != nil && !os.IsExist(err) {
			fmt.Println(err)
		} else {
			fmt.Println("OK, " + path + " successfully created")
		}
	} else {
		fmt.Println("the folder " + path + " does not exist but is required")
		fmt.Println("the service will shut down now")
	}
}

// FileExists reports whether filename exists and is a regular file (not a directory).
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// SeparateFileFromPath splits fullpath into its directory and base filename components.
func SeparateFileFromPath(fullpath string) (path string, filename string) {
	filename = filepath.Base(fullpath)
	path = filepath.Dir(fullpath)
	return path, filename
}

// CheckSum computes the hex-encoded hash of filename using the provided hash algorithm.
func CheckSum(hashAlgorithm hash.Hash, filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

	buf := make([]byte, 65536)
	for {
		switch n, err := bufio.NewReader(file).Read(buf); err {
		case nil:
			hashAlgorithm.Write(buf[:n])
		case io.EOF:
			return fmt.Sprintf("%x", hashAlgorithm.Sum(nil)), nil
		default:
			return "", err
		}
	}
}

// Sort_map_by_value_desc is a stub. TODO: not yet implemented.
func Sort_map_by_value_desc() {}

// Sort_map_by_value_asc is a stub. TODO: not yet implemented.
func Sort_map_by_value_asc() {}

// BuildOutputHeader formats a human-readable header summarizing the analysis.
// If timestamps contains exactly two entries they are shown as a time range.
// The infos map is rendered as key-value pairs below the filename line.
func BuildOutputHeader(logfile string, datetime string, timestamps []string, infos map[string]string) string {
	header := "We analyzed "
	if len(timestamps) == 2 {
		header += "the time between " + timestamps[0] + " and " + timestamps[1] + " in\n"
	}
	header += "the file: " + logfile
	header += "\n================================================================================\n"
	for key, count := range infos {
		header += "\n\t" + key + "\t: " + count
	}
	header += "\n"
	return header
}
