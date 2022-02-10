package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

func readConfigFile(fileName string) ([][]string, error) {
	var domains [][]string
	file, err := os.Open(fileName)
	if err != nil {
		return domains, err
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var lines []string

	for scanner.Scan() {
		text := scanner.Text()
		text = strings.Trim(text, " ")
		if len(text) == 0 {
			continue
		}
		lines = append(lines, scanner.Text())
	}

	file.Close()
	for idx, line := range lines {
		parts := strings.Split(line, " ")
		if len(parts) != 2 {
			return domains, fmt.Errorf("%s: invalid config file at line %d", fileName, idx)
		}
		domains = append(domains, []string{parts[0], parts[1]})
	}
	return domains, nil
}

func main() {
	f, err := os.OpenFile("/var/log/safesearch.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)
	domains, err := readConfigFile("/etc/pihole/safesearch.conf")
	if err != nil {
		log.Panic(err)
	}
	var resolvedInfo [][]string
	for _, domain := range domains {
		r := &net.Resolver{
			PreferGo: true,
		}
		ip, err := r.LookupHost(context.Background(), domain[1])
		if err != nil {
			log.Panic(err)
		}
		resolvedInfo = append(resolvedInfo, []string{ip[0], domain[0]})
	}

	f, err = os.Create("/etc/pihole/custom.list")
	if err != nil {
		log.Panic(err)
	}

	w := bufio.NewWriter(f)

	for _, info := range resolvedInfo {
		w.WriteString(info[0] + " " + info[1] + "\n")
	}

	if err = w.Flush(); err != nil {
		log.Panic(err)
	}
	log.Printf("safesearch successfully updated at %s",
		time.Now().Local().Format(time.RFC1123))
}
