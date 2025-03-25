package main

import (
	"bufio"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ===============
// general helpers
// ===============

func FlagIsPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func StringInSlice(name string, sl []string) bool {
	for _, value := range sl {
		if value == name {
			return true
		}
	}
	return false
}

func GetStringSliceElementIndex(slice []string, value string) int {
	for i, v := range slice {
		if v == value {
			return i
		}
	}
	return -1
}

func GetCleanPath(path string) string {
	return filepath.Clean(path)
}

func checknaddtrailingslash(path *string) {
	if !strings.HasSuffix(*path, "/") {
		*path = *path + "/"
	}
}

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

func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func SeparateFileFromPath(fullpath string) (path string, filename string) {
	filename = filepath.Base(fullpath)
	path = filepath.Dir(fullpath)
	return path, filename
}

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

func Sort_map_by_value_desc() {}
func Sort_map_by_value_asc()  {}
