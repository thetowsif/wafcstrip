package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/cdncheck"
)

// cat /tmp/list_of_IP | wafcstrip -c 100
var (
	concurrency int
	verbose     bool
	writeOutput bool
	nonCdnOut   string
	cdnOut      string
)

var cdnClient *cdncheck.Client
var nonCdnOutputWriter *os.File
var cdnOutputWriter *os.File

// anew-style deduplication: only write lines not already in the output file.
var (
	seenCdn    = make(map[string]struct{})
	seenNonCdn = make(map[string]struct{})
	seenMu     sync.Mutex
)

// loadExisting reads all lines from a file into a set (if the file exists).
func loadExisting(path string) map[string]struct{} {
	set := make(map[string]struct{})
	f, err := os.Open(path)
	if err != nil {
		return set
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			set[line] = struct{}{}
		}
	}
	return set
}

// writeIfNew writes line to w only if it has not been seen before (anew principle).
func writeIfNew(w *os.File, seen map[string]struct{}, line string) {
	seenMu.Lock()
	defer seenMu.Unlock()
	if _, exists := seen[line]; exists {
		return
	}
	seen[line] = struct{}{}
	_, _ = w.WriteString(line + "\n")
}

// liveRange pairs a CIDR network with its vendor name for real-time WAF/CDN checking.
type liveRange struct {
	network *net.IPNet
	vendor  string
}

var liveRanges []liveRange

// awsIPRanges represents the structure of the AWS ip-ranges.json response.
type awsIPRanges struct {
	Prefixes []struct {
		IPPrefix string `json:"ip_prefix"`
		Service  string `json:"service"`
	} `json:"prefixes"`
	IPv6Prefixes []struct {
		IPv6Prefix string `json:"ipv6_prefix"`
		Service    string `json:"service"`
	} `json:"ipv6_prefixes"`
}

func main() {
	// cli arguments
	flag.IntVar(&concurrency, "c", 20, "Set the concurrency level")
	flag.StringVar(&nonCdnOut, "n", "", "Write non-CDN IPs to file")
	flag.StringVar(&cdnOut, "cdn", "", "Write CDN IPs to file")
	flag.BoolVar(&verbose, "v", false, "Verbose output with vendor of CDN")
	flag.Parse()

	var err error
	cdnClient = cdncheck.New()

	// Fetch live WAF/CDN CIDR ranges from Cloudflare, CloudFront, and Akamai
	fetchLiveRanges()

	if nonCdnOut != "" {
		seenNonCdn = loadExisting(nonCdnOut)
		nonCdnOutputWriter, err = os.OpenFile(nonCdnOut, os.O_CREATE|os.O_APPEND|os.O_WRONLY, os.ModePerm)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create/open noneCdnOutputFile\n")
			os.Exit(1)
		}
		defer nonCdnOutputWriter.Close()
		writeOutput = true
	}

	if cdnOut != "" {
		seenCdn = loadExisting(cdnOut)
		cdnOutputWriter, err = os.OpenFile(cdnOut, os.O_CREATE|os.O_APPEND|os.O_WRONLY, os.ModePerm)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create/open notCdnOutputFile\n")
			os.Exit(1)
		}
		defer cdnOutputWriter.Close()
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
				if strings.Contains(line, "/") {
					ip, ipNet, err := net.ParseCIDR(line)
					if err != nil {
						fmt.Fprintf(os.Stderr, "invalid CIDR: %s\n", line)
						continue
					}
					for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
						jobs <- ip.String()
					}
				} else {
					jobs <- line
				}
			}
		}
		close(jobs)
	}()
	wg.Wait()
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// fetchLiveRanges fetches real-time CIDR ranges from Cloudflare, CloudFront, and Akamai.
func fetchLiveRanges() {
	client := &http.Client{Timeout: 15 * time.Second}

	type fetchResult struct {
		ranges []liveRange
		err    error
		name   string
	}

	results := make(chan fetchResult, 5)

	// Cloudflare IPv4
	go func() {
		ranges, err := fetchTextCIDRs(client, "https://www.cloudflare.com/ips-v4", "cloudflare")
		results <- fetchResult{ranges, err, "Cloudflare IPv4"}
	}()

	// Cloudflare IPv6
	go func() {
		ranges, err := fetchTextCIDRs(client, "https://www.cloudflare.com/ips-v6", "cloudflare")
		results <- fetchResult{ranges, err, "Cloudflare IPv6"}
	}()

	// CloudFront (AWS JSON)
	go func() {
		ranges, err := fetchCloudFrontRanges(client)
		results <- fetchResult{ranges, err, "CloudFront"}
	}()

	// Akamai IPv4
	go func() {
		ranges, err := fetchTextCIDRs(client, "https://raw.githubusercontent.com/thetowsif/wafcstrip/refs/heads/master/WAF-List/akamai-ipv4.txt", "akamai")
		results <- fetchResult{ranges, err, "Akamai IPv4"}
	}()

	// Akamai IPv6
	go func() {
		ranges, err := fetchTextCIDRs(client, "https://raw.githubusercontent.com/thetowsif/wafcstrip/refs/heads/master/WAF-List/akamai-ipv6.txt", "akamai")
		results <- fetchResult{ranges, err, "Akamai IPv6"}
	}()

	var allRanges []liveRange
	for i := 0; i < 5; i++ {
		res := <-results
		if res.err != nil {
			fmt.Fprintf(os.Stderr, "[warn] failed to fetch %s ranges: %v\n", res.name, res.err)
			continue
		}
		allRanges = append(allRanges, res.ranges...)
	}

	liveRanges = allRanges
	if len(liveRanges) > 0 {
		fmt.Fprintf(os.Stderr, "[info] loaded %d live WAF/CDN CIDR ranges\n", len(liveRanges))
	}
}

// fetchTextCIDRs fetches a newline-separated list of CIDRs from a URL.
func fetchTextCIDRs(client *http.Client, rawURL, vendor string) ([]liveRange, error) {
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var ranges []liveRange
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		_, network, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		ranges = append(ranges, liveRange{network: network, vendor: vendor})
	}
	return ranges, nil
}

// fetchCloudFrontRanges fetches CloudFront CIDR ranges from the AWS ip-ranges.json endpoint.
func fetchCloudFrontRanges(client *http.Client) ([]liveRange, error) {
	resp, err := client.Get("https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data awsIPRanges
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var ranges []liveRange
	for _, p := range data.Prefixes {
		if p.Service == "CLOUDFRONT" {
			_, network, err := net.ParseCIDR(p.IPPrefix)
			if err != nil {
				continue
			}
			ranges = append(ranges, liveRange{network: network, vendor: "cloudfront"})
		}
	}
	for _, p := range data.IPv6Prefixes {
		if p.Service == "CLOUDFRONT" {
			_, network, err := net.ParseCIDR(p.IPv6Prefix)
			if err != nil {
				continue
			}
			ranges = append(ranges, liveRange{network: network, vendor: "cloudfront"})
		}
	}
	return ranges, nil
}

// checkLiveRanges checks if an IP matches any of the live WAF/CDN CIDR ranges.
func checkLiveRanges(ip net.IP) (bool, string) {
	for _, lr := range liveRanges {
		if lr.network.Contains(ip) {
			return true, lr.vendor
		}
	}
	return false, ""
}

func cdnChecking(ip string) {
	// in case input as http format
	if strings.HasPrefix(ip, "http") {
		uu, err := url.Parse(ip)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse url: %s\n", err)
			return
		}
		ip = uu.Hostname()
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		fmt.Fprintf(os.Stderr, "invalid IP: %s\n", ip)
		return
	}

	var vendor, ipType string
	matched := false

	// First: check via cdncheck library (fast, uses optimized data structures)
	_, vendor, ipType, err := cdnClient.Check(parsedIP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error checking IP: %s\n", err)
		return
	}

	if ipType == "cdn" || ipType == "waf" {
		matched = true
	}

	// Second: if cdncheck didn't match, check against live-fetched ranges
	if !matched {
		if liveMatched, liveVendor := checkLiveRanges(parsedIP); liveMatched {
			matched = true
			vendor = liveVendor
			ipType = "cdn"
		}
	}

	if vendor == "" {
		vendor = "unknown"
	}
	if ipType == "" {
		ipType = "unknown"
	}

	line := ip

	if verbose {
		line = fmt.Sprintf("%s,%s,%s", vendor, ipType, ip)
		fmt.Println(line)
	}

	if matched {
		if writeOutput {
			writeIfNew(cdnOutputWriter, seenCdn, ip)
		}
		return
	}

	if !verbose {
		fmt.Println(line)
	}

	if writeOutput {
		writeIfNew(nonCdnOutputWriter, seenNonCdn, ip)
	}
}
