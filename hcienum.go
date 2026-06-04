package gobtusb

import (
	"fmt"
	"strings"

	"github.com/google/gousb"
)

// HCIControllerInfo describes a USB Bluetooth controller
type HCIControllerInfo struct {
	VendorID  uint16
	ProductID uint16
	Serial    string // USB serial number; may be "" if the descriptor read failed
	Interface int    // bInterfaceNumber of the Wireless Controller function
}

func (i HCIControllerInfo) String() string {
	return fmt.Sprintf("%04x:%04x serial %q (interface %d)", i.VendorID, i.ProductID, i.Serial, i.Interface)
}

// ListHCIControllers enumerates USB devices with Wireless Controller interface.
// non-platform specific reads require libusb to claim the device to read the serial number
// which may be slow in some conditions.
func ListHCIControllers() ([]HCIControllerInfo, error) {
	ctx := gousb.NewContext()
	defer ctx.Close()

	devs, err := openWirelessDevices(ctx)
	var out []HCIControllerInfo
	for _, d := range devs {
		out = append(out, controllerInfo(d))
		d.Close()
	}
	if len(out) == 0 && err != nil {
		return nil, fmt.Errorf("enumerate USB controllers: %w", err)
	}
	return out, nil
}

func openWirelessDevices(ctx *gousb.Context) ([]*gousb.Device, error) {
	return ctx.OpenDevices(func(desc *gousb.DeviceDesc) bool {
		return wirelessInterface(desc) >= 0
	})
}

func wirelessInterface(desc *gousb.DeviceDesc) int {
	for _, cfg := range desc.Configs {
		for _, intf := range cfg.Interfaces {
			for _, alt := range intf.AltSettings {
				if alt.Class == gousb.ClassWireless {
					return intf.Number
				}
			}
		}
	}
	return -1
}

func controllerInfo(d *gousb.Device) HCIControllerInfo {
	serial, _ := d.SerialNumber()
	return HCIControllerInfo{
		VendorID:  uint16(d.Desc.Vendor),
		ProductID: uint16(d.Desc.Product),
		Serial:    serial,
		Interface: wirelessInterface(d.Desc),
	}
}

// openController opens the first attached USB Bluetooth controller matching
// opts and returns it with the interface number of its HCI function. With zero
// opts any device exposing a Wireless Controller interface matches; Serial is
// disambiguating when several are attached.
func openController(ctx *gousb.Context, opts HCIOptions) (*gousb.Device, int, error) {
	if opts.Serial != "" {
		dev, iface, err := openControllerBySerial(ctx, opts.Serial)
		if err != nil {
			return nil, 0, err
		}
		if opts.Interface != 0 {
			iface = opts.Interface
		}
		return dev, iface, nil
	}

	var match *gousb.Device
	devs, err := ctx.OpenDevices(func(desc *gousb.DeviceDesc) bool {
		if opts.VendorID != 0 && uint16(desc.Vendor) != opts.VendorID {
			return false
		}
		if opts.ProductID != 0 && uint16(desc.Product) != opts.ProductID {
			return false
		}
		if opts.Interface != 0 {
			return true // explicit interface; claim() verifies its class
		}
		return wirelessInterface(desc) >= 0
	})
	for _, d := range devs {
		if match == nil {
			match = d
			continue
		}
		d.Close()
	}
	if match == nil {
		want := describeFilter(opts)
		if err != nil {
			return nil, 0, fmt.Errorf("%w: no USB Bluetooth controller matching %s: %v", ErrNotEnabled, want, err)
		}
		return nil, 0, fmt.Errorf("%w: no USB Bluetooth controller matching %s", ErrNotEnabled, want)
	}
	iface := opts.Interface
	if iface == 0 {
		iface = wirelessInterface(match.Desc)
	}
	return match, iface, nil
}

// describeFilter renders the controller-selection criteria for error messages.
func describeFilter(opts HCIOptions) string {
	var parts []string
	if opts.VendorID != 0 {
		parts = append(parts, fmt.Sprintf("vendor %04x", opts.VendorID))
	}
	if opts.ProductID != 0 {
		parts = append(parts, fmt.Sprintf("product %04x", opts.ProductID))
	}
	if opts.Interface != 0 {
		parts = append(parts, fmt.Sprintf("interface %d", opts.Interface))
	}
	if len(parts) == 0 {
		return "any Wireless Controller interface"
	}
	return strings.Join(parts, ", ")
}

func openControllerBySerial(ctx *gousb.Context, serial string) (*gousb.Device, int, error) {
	devs, err := openWirelessDevices(ctx)
	var match *gousb.Device
	var seen []HCIControllerInfo
	for _, d := range devs {
		info := controllerInfo(d)
		if match == nil && strings.EqualFold(info.Serial, serial) {
			match = d
			continue
		}
		seen = append(seen, info)
		d.Close()
	}
	if match == nil {
		if len(seen) == 0 {
			if err != nil {
				return nil, 0, fmt.Errorf("%w: no USB Bluetooth controller with serial %q (%v)", ErrNotEnabled, serial, err)
			}
			return nil, 0, fmt.Errorf("%w: no USB Bluetooth controller with serial %q (none attached)", ErrNotEnabled, serial)
		}
		descs := make([]string, len(seen))
		for i, info := range seen {
			descs[i] = info.String()
		}
		return nil, 0, fmt.Errorf("%w: no USB Bluetooth controller with serial %q; attached controllers: %s",
			ErrNotEnabled, serial, strings.Join(descs, ", "))
	}
	return match, wirelessInterface(match.Desc), nil
}
