package gobtusb_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/kendallgoto/gobtusb"
)

// Scan for nearby peripherals and print each advertisement.
func ExampleAdapter_Scan() {
	adapter, err := gobtusb.DefaultAdapter()
	if err != nil {
		log.Fatal(err)
	}
	if err := adapter.Enable(context.Background()); err != nil {
		log.Fatal(err)
	}

	// Scan runs in the background until StopScan.
	err = adapter.Scan(func(r gobtusb.ScanResult) {
		fmt.Printf("%s %ddBm %q\n", r.Address, r.RSSI, r.LocalName())
	})
	if err != nil {
		log.Fatal(err)
	}
	time.Sleep(5 * time.Second)
	adapter.StopScan()
}

// Connect to a peripheral, subscribe to notifications from a characteristic,
// and write a value to it.
func ExampleAdapter_Connect() {
	ctx := context.Background()
	adapter, err := gobtusb.DefaultAdapter()
	if err != nil {
		log.Fatal(err)
	}
	if err := adapter.Enable(ctx); err != nil {
		log.Fatal(err)
	}

	addr, err := gobtusb.ParseAddress("AA:BB:CC:DD:EE:FF")
	if err != nil {
		log.Fatal(err)
	}
	device, err := adapter.Connect(ctx, *addr, gobtusb.ConnectParams{})
	if err != nil {
		log.Fatal(err)
	}
	defer device.Disconnect()

	services, err := device.DiscoverServices([]gobtusb.UUID{gobtusb.New16BitUUID(0x180D)})
	if err != nil {
		log.Fatal(err)
	}
	chars, err := services[0].DiscoverCharacteristics(nil)
	if err != nil {
		log.Fatal(err)
	}
	char := chars[0]

	err = char.EnableNotifications(func(value []byte) {
		fmt.Printf("notification: % x\n", value)
	})
	if err != nil {
		log.Fatal(err)
	}

	if _, err := char.WriteWithoutResponse([]byte{0x01}); err != nil {
		log.Fatal(err)
	}
}

// Open a USB HCI controller explicitly.
func ExampleNewHCIAdapter() {
	adapter, err := gobtusb.NewHCIAdapter(gobtusb.HCIOptions{})
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := adapter.Enable(ctx); err != nil {
		log.Fatal(err)
	}
}
