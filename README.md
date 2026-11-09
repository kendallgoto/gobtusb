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

## Bonding (USB HCI backend)

OS backends (CoreBluetooth) pair and keep bonds themselves. The USB HCI backend talks to a bare controller, so it implements the Security Manager itself and stores bonds in a `BondStore` you provide:

```go
type BondStore interface {
    Load() (gobtusb.BondState, error)
    Save(gobtusb.BondState) error
}

adapter, err := gobtusb.NewHCIAdapter(gobtusb.HCIOptions{Bonds: myStore})
```

- Pairing is LE Secure Connections only (legacy pairing is rejected). The host offers DisplayYesNo and requests MITM protection, so a peer that can confirm a number pairs with Numeric Comparison (authenticated, security level 4), and a peer without IO falls back to Just Works (level 2). Passkey entry is not supported. Set `HCIOptions.ConfirmPasskey` to show the comparison value and accept or reject it; when nil, every value is accepted, which satisfies a level 4 peer but gives no more MITM protection than Just Works.
- Pairing starts automatically when the peripheral sends a Security Request or rejects an ATT request with Insufficient Authentication / Encryption, after which the request is retried.
- When bonded, the link is encrypted with the stored LTK. If the peer has lost the bond (e.g. after a factory reset), the stale bond is deleted and the link re-paired.
- The peer's IRK is requested so its resolvable private addresses resolve: scan results and `Device.Address()` report a bonded peer by its identity address, and `Connect` accepts that address.
- `BondState.LocalAddress` is the host's random static address. Peers recognize the bond by it, so it is generated once and persisted. With no `BondStore`, bonds last only as long as the adapter.

## Debugging (USB HCI backend)

- `HCIOptions.Logf` receives one line per link-level operation: connection setup and parameter updates, MTU exchange, Security Requests, each pairing step, encryption changes, ATT errors that trigger pairing, and disconnect reasons.
- A connected HCI `Device` implements `GATTTabler`. `GATTTable()` walks every primary service, characteristic and descriptor with their handles, and reads each readable value (up to ATT_MTU-1 bytes). A failed read is recorded on the attribute instead of stopping the walk.
