// Command btcli exercises gobtusb from the command line: list controllers,
// scan, connect and walk GATT, write, subscribe to notifications, pair, and
// manage bonds. It doubles as a set of sample workflows for the library.
//
//	btcli scan -t 5s -name Sensor
//	btcli -hci -v gatt c6:12:34:56:78:9a
//	btcli -hci write c6:12:34:56:78:9a 2a06 01
//	btcli -hci notify c6:12:34:56:78:9a 2a37
//	btcli -hci pair c6:12:34:56:78:9a
//	btcli bonds -delete c6:12:34:56:78:9a
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kendallgoto/gobtusb"
)

var (
	useHCI   = flag.Bool("hci", false, "use a USB HCI controller instead of the OS Bluetooth stack")
	serial   = flag.String("serial", "", "with -hci, select the controller by USB serial number")
	bondPath = flag.String("bonds", defaultBondPath(), "with -hci, file to keep the local address and bonds in (empty: memory only)")
	verbose  = flag.Bool("v", false, "with -hci, log link-level operations (connection, MTU, pairing, encryption)")
	timeout  = flag.Duration("timeout", 15*time.Second, "how long to look for and connect to a device")
)

var commands = []struct {
	name, args, help string
	run              func(args []string) error
}{
	{"controllers", "", "list attached USB Bluetooth controllers", cmdControllers},
	{"scan", "[-t 5s] [-uuid U] [-name S] [-raw]", "scan and list advertising devices", cmdScan},
	{"gatt", "<addr>", "connect and print the GATT table", cmdGATT},
	{"write", "[-noresp] <addr> <char-uuid> <hex>", "write a value to a characteristic", cmdWrite},
	{"notify", "[-t dur] <addr> <char-uuid>", "subscribe and print notifications until Ctrl-C", cmdNotify},
	{"pair", "<addr>", "connect and pair/encrypt the link (-hci only)", cmdPair},
	{"bonds", "[-delete addr]", "list or delete stored bonds (-hci only)", cmdBonds},
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() == 0 {
		usage()
		os.Exit(2)
	}
	for _, c := range commands {
		if c.name == flag.Arg(0) {
			if err := c.run(flag.Args()[1:]); err != nil {
				log.Fatal(err)
			}
			return
		}
	}
	usage()
	os.Exit(2)
}

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "usage: btcli [flags] <command> [args]\n\ncommands:\n")
	for _, c := range commands {
		fmt.Fprintf(out, "  %-12s %-38s %s\n", c.name, c.args, c.help)
	}
	fmt.Fprintf(out, "\nflags:\n")
	flag.PrintDefaults()
	fmt.Fprintf(out, "\nAddresses are MACs (aa:bb:cc:dd:ee:ff) with -hci, or CoreBluetooth\nidentifiers on macOS without it; run scan to find them.\n")
}

func defaultBondPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".btcli", "bonds.json")
}

// openAdapter returns the selected backend, enabled.
func openAdapter() (gobtusb.Adapter, error) {
	var a gobtusb.Adapter
	var err error
	if *useHCI {
		opts := gobtusb.HCIOptions{Serial: *serial}
		if *bondPath != "" {
			opts.Bonds = fileBondStore(*bondPath)
		}
		if *verbose {
			opts.Logf = func(format string, args ...any) { log.Printf("hci: "+format, args...) }
		}
		opts.ConfirmPasskey = func(passkey uint32) bool {
			log.Printf("pairing: numeric comparison %06d (accepting)", passkey)
			return true
		}
		a, err = gobtusb.NewHCIAdapter(opts)
	} else {
		a, err = gobtusb.DefaultAdapter()
	}
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.Enable(ctx); err != nil {
		closeAdapter(a)
		return nil, fmt.Errorf("enable adapter: %w", err)
	}
	if c, ok := a.(controllerInfo); ok {
		log.Printf("using controller %s", c.Controller())
	}
	return a, nil
}

// controllerInfo is implemented by the HCI adapter.
type controllerInfo interface {
	Controller() gobtusb.HCIControllerInfo
}

func closeAdapter(a gobtusb.Adapter) {
	if c, ok := a.(io.Closer); ok {
		c.Close()
	}
}

// connect scans until addr advertises, then connects to it. Both backends
// need the scan: CoreBluetooth only connects to peripherals it has seen, and
// over HCI the scan tells us whether the address is public or random.
func connect(a gobtusb.Adapter, addr string) (gobtusb.Device, error) {
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	found := make(chan gobtusb.Address, 1)
	err := a.Scan(func(r gobtusb.ScanResult) {
		if strings.EqualFold(r.Address.String(), addr) {
			select {
			case found <- r.Address:
			default:
			}
		}
	})
	if err != nil {
		return nil, err
	}
	log.Printf("scanning for %s ...", addr)
	var target gobtusb.Address
	select {
	case target = <-found:
	case <-ctx.Done():
		a.StopScan()
		return nil, fmt.Errorf("%s not seen within %s", addr, *timeout)
	}
	a.StopScan()

	dev, err := a.Connect(ctx, target, gobtusb.ConnectParams{})
	if err != nil {
		return nil, err
	}
	log.Printf("connected to %s", dev.Address())
	return dev, nil
}

// withDevice opens the adapter, connects to addr, runs fn and cleans up.
func withDevice(addr string, fn func(gobtusb.Device) error) error {
	a, err := openAdapter()
	if err != nil {
		return err
	}
	defer closeAdapter(a)
	dev, err := connect(a, addr)
	if err != nil {
		return err
	}
	defer func() {
		dev.Disconnect()
		log.Printf("disconnected")
	}()
	return fn(dev)
}

func cmdControllers(args []string) error {
	cs, err := gobtusb.ListHCIControllers()
	if err != nil {
		return err
	}
	if len(cs) == 0 {
		fmt.Println("no USB Bluetooth controllers found")
	}
	for _, c := range cs {
		fmt.Println(c)
	}
	return nil
}

func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	dur := fs.Duration("t", 5*time.Second, "scan duration")
	uuidArg := fs.String("uuid", "", "only devices advertising this service UUID (e.g. 180d)")
	name := fs.String("name", "", "only devices whose name contains this (case-insensitive)")
	raw := fs.Bool("raw", false, "print each device's AD structures and which packet they came in")
	fs.Parse(args)

	var want *gobtusb.UUID
	if *uuidArg != "" {
		u, err := gobtusb.ParseUUID(*uuidArg)
		if err != nil {
			return err
		}
		want = &u
	}

	a, err := openAdapter()
	if err != nil {
		return err
	}
	defer closeAdapter(a)

	// Keep the latest result per device: the name and other data may only
	// arrive in a scan response after the first advertisement.
	var mu sync.Mutex
	var order []string
	latest := map[string]gobtusb.ScanResult{}
	names := map[string]string{}
	err = a.Scan(func(r gobtusb.ScanResult) {
		mu.Lock()
		defer mu.Unlock()
		k := r.Address.String()
		if _, ok := latest[k]; !ok {
			order = append(order, k)
		}
		latest[k] = r
		if n := r.LocalName(); n != "" {
			names[k] = n
		}
	})
	if err != nil {
		return err
	}
	log.Printf("scanning for %s ...", *dur)
	time.Sleep(*dur)
	if err := a.StopScan(); err != nil {
		return err
	}

	mu.Lock()
	defer mu.Unlock()
	shown := 0
	for _, k := range order {
		r := latest[k]
		if want != nil && !slices.Contains(r.ServiceUUIDs(), *want) {
			continue
		}
		if *name != "" && !strings.Contains(strings.ToLower(names[k]), strings.ToLower(*name)) {
			continue
		}
		shown++
		var uuids []string
		for _, u := range r.ServiceUUIDs() {
			uuids = append(uuids, shortUUID(u))
		}
		fmt.Printf("%s  %4ddBm  %-20q  %s\n", k, r.RSSI, names[k], strings.Join(uuids, ","))
		if *raw {
			for _, ad := range r.Structures() {
				fmt.Printf("    %-13s type 0x%02x  %s\n", ad.Source, ad.Type, hex.EncodeToString(ad.Data))
			}
		}
	}
	log.Printf("%d of %d devices shown", shown, len(order))
	return nil
}

func cmdGATT(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: gatt <addr>")
	}
	return withDevice(args[0], func(dev gobtusb.Device) error {
		if t, ok := dev.(gobtusb.GATTTabler); ok {
			table, err := t.GATTTable()
			if err != nil {
				return err
			}
			printTable(table)
			return nil
		}
		// OS backends hide handles and values; list what they do expose.
		services, err := dev.DiscoverServices(nil)
		if err != nil {
			return err
		}
		for _, s := range services {
			fmt.Printf("service %s\n", shortUUID(s.UUID()))
			chars, err := s.DiscoverCharacteristics(nil)
			if err != nil {
				return err
			}
			for _, c := range chars {
				fmt.Printf("  char %s\n", shortUUID(c.UUID()))
			}
		}
		return nil
	})
}

func printTable(table []gobtusb.GATTService) {
	for _, s := range table {
		fmt.Printf("service %s  [0x%04x-0x%04x]\n", shortUUID(s.UUID), s.Start, s.End)
		for _, c := range s.Characteristics {
			fmt.Printf("  char %s  decl 0x%04x  value 0x%04x  [%s]%s\n", shortUUID(c.UUID), c.Handle, c.ValueHandle,
				strings.Join(c.PropertyNames(), ","), formatValue(c.Value, c.ReadErr, c.Properties&gobtusb.PropRead != 0))
			for _, d := range c.Descriptors {
				fmt.Printf("    desc %s  0x%04x%s\n", shortUUID(d.UUID), d.Handle, formatValue(d.Value, d.ReadErr, true))
			}
		}
	}
}

func formatValue(v []byte, readErr string, readable bool) string {
	switch {
	case !readable:
		return ""
	case readErr != "":
		return "  (" + readErr + ")"
	case printable(v):
		return fmt.Sprintf("  = %s %q", hex.EncodeToString(v), v)
	}
	return "  = " + hex.EncodeToString(v)
}

func printable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func shortUUID(u gobtusb.UUID) string {
	if u.Is16Bit() {
		return fmt.Sprintf("%04x", u.Get16Bit())
	}
	return u.String()
}

// findChar returns the first characteristic with the given UUID, in any service.
func findChar(dev gobtusb.Device, s string) (gobtusb.Characteristic, error) {
	uuid, err := gobtusb.ParseUUID(s)
	if err != nil {
		return nil, err
	}
	services, err := dev.DiscoverServices(nil)
	if err != nil {
		return nil, err
	}
	for _, svc := range services {
		chars, err := svc.DiscoverCharacteristics([]gobtusb.UUID{uuid})
		if err != nil {
			return nil, err
		}
		if len(chars) > 0 {
			return chars[0], nil
		}
	}
	return nil, fmt.Errorf("characteristic %s not found", s)
}

func cmdWrite(args []string) error {
	fs := flag.NewFlagSet("write", flag.ExitOnError)
	noResp := fs.Bool("noresp", false, "use Write Without Response")
	fs.Parse(args)
	if fs.NArg() != 3 {
		return errors.New("usage: write [-noresp] <addr> <char-uuid> <hex>")
	}
	value, err := hex.DecodeString(strings.ReplaceAll(fs.Arg(2), " ", ""))
	if err != nil {
		return fmt.Errorf("value: %w", err)
	}
	return withDevice(fs.Arg(0), func(dev gobtusb.Device) error {
		c, err := findChar(dev, fs.Arg(1))
		if err != nil {
			return err
		}
		if *noResp {
			_, err = c.WriteWithoutResponse(value)
		} else {
			_, err = c.Write(value)
		}
		if err != nil {
			return err
		}
		log.Printf("wrote %d bytes to %s", len(value), fs.Arg(1))
		return nil
	})
}

func cmdNotify(args []string) error {
	fs := flag.NewFlagSet("notify", flag.ExitOnError)
	dur := fs.Duration("t", 0, "stop after this long (0: until Ctrl-C or disconnect)")
	fs.Parse(args)
	if fs.NArg() != 2 {
		return errors.New("usage: notify [-t dur] <addr> <char-uuid>")
	}
	return withDevice(fs.Arg(0), func(dev gobtusb.Device) error {
		c, err := findChar(dev, fs.Arg(1))
		if err != nil {
			return err
		}
		err = c.EnableNotifications(func(v []byte) {
			log.Printf("notify %s: %s", fs.Arg(1), hex.EncodeToString(v))
		})
		if err != nil {
			return err
		}
		log.Printf("subscribed to %s; Ctrl-C to stop", fs.Arg(1))

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		var stop <-chan time.Time
		if *dur > 0 {
			stop = time.After(*dur)
		}
		select {
		case <-sig:
		case <-stop:
		case <-dev.Disconnected():
			return errors.New("device disconnected")
		}
		return c.DisableNotifications()
	})
}

func cmdPair(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: pair <addr>")
	}
	if !*useHCI {
		return errors.New("pair needs -hci; the OS stack pairs on its own when a characteristic requires it")
	}
	return withDevice(args[0], func(dev gobtusb.Device) error {
		s, ok := dev.(gobtusb.Securer)
		if !ok {
			return errors.New("backend does not support pairing on demand")
		}
		if err := s.Secure(); err != nil {
			return err
		}
		log.Printf("link encrypted; device identity %s", dev.Address())
		return nil
	})
}

func cmdBonds(args []string) error {
	fs := flag.NewFlagSet("bonds", flag.ExitOnError)
	del := fs.String("delete", "", "delete the bond with this identity address")
	fs.Parse(args)
	if *bondPath == "" {
		return errors.New("no bond file (-bonds)")
	}
	store := fileBondStore(*bondPath)
	st, err := store.Load()
	if err != nil {
		return err
	}
	if *del != "" {
		n := len(st.Bonds)
		st.Bonds = slices.DeleteFunc(st.Bonds, func(b gobtusb.Bond) bool {
			return strings.EqualFold(b.Address.String(), *del)
		})
		if len(st.Bonds) == n {
			return fmt.Errorf("no bond for %s", *del)
		}
		if err := store.Save(st); err != nil {
			return err
		}
		log.Printf("deleted bond for %s", *del)
		return nil
	}
	fmt.Printf("bond file      %s\n", *bondPath)
	if st.LocalAddress == (gobtusb.Address{}) {
		fmt.Println("local address  (none yet; generated on first -hci use)")
	} else {
		fmt.Printf("local address  %s\n", st.LocalAddress)
	}
	for _, b := range st.Bonds {
		kind := "public"
		if b.Address.IsRandom {
			kind = "random"
		}
		fmt.Printf("bond           %s (%s)  irk %x\n", b.Address, kind, b.IRK)
	}
	if len(st.Bonds) == 0 {
		fmt.Println("no bonds")
	}
	return nil
}
