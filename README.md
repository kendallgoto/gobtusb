# gobtusb

A condensed BLE GATT Central library for Go, featuring the minimum features required for talking to typical BLE IoT devices:
- Scanning for advertisements
- Connecting to peripherals
- Writing to characteristics (with/without response)
- Receiving notifications from characteristic

It is inspired by [`tinygo.org/x/bluetooth`](https://github.com/tinygo-org/bluetooth) but features more complete support for HCI USB devices as a priority, rather than just OS abstractions. It also isn't designed for bare-metal systems as TinyGo is typically designed for.

## Install

We always include the USB-HCI backend, so libusb and CGO are required on all platforms.

```sh
# macOS
brew install libusb
# Debian/Ubuntu
sudo apt install libusb-1.0-0-dev

go get github.com/kendallgoto/gobtusb
```

## Usage

```go
adapter, err := gobtusb.DefaultAdapter()
if err != nil {
    log.Fatal(err)
}
if err := adapter.Enable(); err != nil {
    log.Fatal(err)
}

// Scan for 5 seconds.
time.AfterFunc(5*time.Second, func() { adapter.StopScan() })
adapter.Scan(func(r gobtusb.ScanResult) {
    fmt.Printf("%s %ddBm %q\n", r.Address, r.RSSI, r.LocalName())
})
```
