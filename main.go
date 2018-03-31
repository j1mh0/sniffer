package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var wg sync.WaitGroup

func sniff(ctx context.Context, device string, promiscuous bool, expression string) {

	wg.Add(1)
	defer wg.Done()

	var (
		snapshotLen int32 = 1024
		err         error
		timeout     time.Duration = 30 * time.Second
		handle      *pcap.Handle
	)

	// Open device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer handle.Close()

	//Set BPFilter
	if expression != "" {
		if err := handle.SetBPFFilter(expression); err != nil {
			fmt.Printf("Filter Expression (%v) Error!\n", expression)
			return
		}
	}

	//Print device name and mode
	fmt.Printf("Sniffer on %v...", device)
	if promiscuous {
		fmt.Print("(promiscuous mode)")
	}
	fmt.Println()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	//packet counter
	var packetCount int64

	for {
		select {
		case packet := <-packetSource.Packets():
			// Process packet here
			fmt.Println(packet)
			packetCount++
		case <-ctx.Done():
			// Print packets counter and exit goroutine
			fmt.Printf("\n%v packets captured.\n", packetCount)
			return
		}
	}

}

//main function
func main() {

	var expression string

	device := flag.String("i", "eth0", "device name")
	promiscuous := flag.Bool("p", false, "promiscuous mode")

	flag.Parse()
	expressionArgs := flag.Args()
	if len(expressionArgs) != 0 {
		expression = strings.Join(expressionArgs, " ")
	}

	ctx, cancel := context.WithCancel(context.Background())

	go sniff(ctx, *device, *promiscuous, expression)

	c := make(chan os.Signal)
	signal.Notify(c, os.Kill, os.Interrupt)
	select {
	case <-c:
		cancel()
		wg.Wait()
	}

}
