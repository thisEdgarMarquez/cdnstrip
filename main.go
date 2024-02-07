package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/projectdiscovery/cdncheck"
)

// cat /tmp/list_of_IP | cdnstrip -c 100
var (
	concurrency int
	verbose     bool
	writeOutput bool
	output      string
	cdnMatch    string
)

var cdnClient *cdncheck.Client
var OutputWriter *os.File

func main() {
	// cli arguments
	flag.IntVar(&concurrency, "c", 20, "Set the concurrency level")
	flag.StringVar(&output, "o", "", "Write results to file")
	flag.StringVar(&cdnMatch, "cdnMatch", "", "CDN Match")
	flag.BoolVar(&verbose, "v", false, "Verbose output with vendor of CDN")
	flag.Parse()

	var err error
	cdnClient = cdncheck.New()

	if output != "" {
		OutputWriter, err = os.OpenFile(output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, os.ModePerm)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create/open noneCdnOutputFile\n")
			os.Exit(1)
		}
		defer OutputWriter.Close()
		writeOutput = true
	}

	var wg sync.WaitGroup
	jobs := make(chan string, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				// actually start checking
				cdnChecking(job)
			}
		}()
	}

	sc := bufio.NewScanner(os.Stdin)
	go func() {
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if err := sc.Err(); err == nil && line != "" {
				jobs <- line
			}
		}
		close(jobs)
	}()
	wg.Wait()
}

func cdnChecking(ip string) {
	// in case input as http format
	if strings.HasPrefix(ip, "http") {
		// parse url
		uu, err := url.Parse(ip)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse url: %s\n", err)
			return
		}
		ip = uu.Hostname()
	}

	if found, cdnprovider, _, _ := cdnClient.CheckDomainWithFallback(ip); found {
		if cdnMatch != "" {
			if strings.Contains(cdnMatch, cdnprovider) {
				if writeOutput {
					OutputWriter.WriteString(ip + "\n")
				}
			}
		} else {
			if writeOutput {
				OutputWriter.WriteString(ip + "\n")
			} else {
				fmt.Println(ip)
			}
		}
	}
}
