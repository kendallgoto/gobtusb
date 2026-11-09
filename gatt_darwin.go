package gobtusb

import (
	"fmt"
	"time"

	"github.com/tinygo-org/cbgo"
)

type coreBluetoothCharacteristic struct {
	dev *coreBluetoothDevice
	chr cbgo.Characteristic
}

func (c *coreBluetoothCharacteristic) UUID() UUID { return fromCBUUID(c.chr.UUID()) }

func (c *coreBluetoothCharacteristic) Write(p []byte) (int, error) {
	err := c.dev.run(func() { c.dev.prph.WriteCharacteristic(p, c.chr, true) })
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// WriteWithoutResponse queues p, first waiting until CoreBluetooth has room:
// it silently drops writes made while canSendWriteWithoutResponse is false.
func (c *coreBluetoothCharacteristic) WriteWithoutResponse(p []byte) (int, error) {
	d := c.dev
	timeout := time.After(cbOpTimeout)
	for !d.prph.CanSendWriteWithoutResponse() {
		select {
		case <-d.wwrReady:
		case <-d.disc:
			return 0, ErrNotConnected
		case <-timeout:
			return 0, fmt.Errorf("write without response to %s: timed out waiting for CoreBluetooth to accept it", c.UUID())
		}
	}
	d.prph.WriteCharacteristic(p, c.chr, false)
	return len(p), nil
}

func (c *coreBluetoothCharacteristic) EnableNotifications(callback func([]byte)) error {
	if c.chr.Properties()&(cbgo.CharacteristicPropertyNotify|cbgo.CharacteristicPropertyIndicate) == 0 {
		return fmt.Errorf("%w: characteristic %s does not support notifications", ErrCharacteristicNotFound, c.UUID())
	}
	c.dev.notifyMu.Lock()
	c.dev.notify[c.UUID().String()] = callback
	c.dev.notifyMu.Unlock()

	if err := c.dev.run(func() { c.dev.prph.SetNotify(true, c.chr) }); err != nil {
		c.dev.notifyMu.Lock()
		delete(c.dev.notify, c.UUID().String())
		c.dev.notifyMu.Unlock()
		return err
	}
	return nil
}

func (c *coreBluetoothCharacteristic) DisableNotifications() error {
	err := c.dev.run(func() { c.dev.prph.SetNotify(false, c.chr) })
	c.dev.notifyMu.Lock()
	delete(c.dev.notify, c.UUID().String())
	c.dev.notifyMu.Unlock()
	return err
}

// encodeAdvFields re-encodes CoreBluetooth fields into a raw advertising payload for uniform decoding upstream
func encodeAdvFields(f cbgo.AdvFields) []byte {
	var out []byte
	if f.LocalName != "" {
		out = appendAD(out, adTypeCompleteLocalName, []byte(f.LocalName))
	}
	var u16, u128 []byte
	for _, u := range f.ServiceUUIDs {
		g := fromCBUUID(u)
		if g.Is16Bit() {
			s := g.Get16Bit()
			u16 = append(u16, byte(s), byte(s>>8))
		} else {
			for i := range 16 {
				u128 = append(u128, g[15-i])
			}
		}
	}
	if len(u16) > 0 {
		out = appendAD(out, 0x03, u16)
	}
	if len(u128) > 0 {
		out = appendAD(out, 0x07, u128)
	}
	for _, sd := range f.ServiceData {
		out = appendServiceData(out, fromCBUUID(sd.UUID), sd.Data)
	}
	return out
}
