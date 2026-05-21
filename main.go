package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/go-ping/ping"
)

func main() {
	subnet := "192.168.31."
	var wg sync.WaitGroup

	for i := 1; i < 255; i++ {
		ip := fmt.Sprintf("%s%d", subnet, i)
		wg.Add(1)

		go func(targetIP string) {
			defer wg.Done()

			pinger, err := ping.NewPinger(targetIP)
			if err != nil {
				return
			}
			pinger.Count = 1
			pinger.Timeout = time.Millisecond * 500
			pinger.Run()

			stats := pinger.Statistics()
			if stats.PacketsRecv > 0 {
				fmt.Printf("Device found: %s\n", targetIP)
			}
		}(ip)
	}

	wg.Wait()
	fmt.Println("Scan completed")
}
