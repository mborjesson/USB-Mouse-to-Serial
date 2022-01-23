# USB Mouse to Serial

This Linux-program will make a computer act as an adapter for a USB mouse to serial port. It was developed for Raspberry Pi in mind to be able to use a modern USB mouse on older computers that only has a serial port.

Click [here](https://www.youtube.com/watch?v=vAz2g2S6Rmw) to see a demonstration of what the program can do.

[![Demonstration video](https://img.youtube.com/vi/vAz2g2S6Rmw/0.jpg)](https://www.youtube.com/watch?v=vAz2g2S6Rmw)

## Features

* Four mouse protocols to emulate
* Remote Configuration API
* Suspend the USB mouse when power is off

## Requirements

* Raspberry Pi running Raspbian - tested on a RPi 2 Model B running 2017-11-29-raspbian-stretch-lite
* Serial port - for example a USB to serial port adapter (there may be issues with certain adapters, see [issue #7](https://github.com/mborjesson/USB-Mouse-to-Serial/issues/7))
* Null modem cable
* libevdev

## Mouse Protocols

* Microsoft 2-button mouse (microsoft) [right]
* Logitech 3-button mouse (logitech) [left and right]
* Microsoft 3-button wheel mouse (wheel) [middle]
* Mouse Systems (mousesystems) [left]

The protocol can be set when starting the program by using the protocol-parameter and the value in parentheses, like this: `usb_mouse_to_serial --protocol mousesystems`

The protocol can also be changed on-the-fly by pressing the mouse button(s) in square brackets during the DSR/CTS toggle when loading the mouse driver on the computer (will be reset to requested/default protocol after a power cycle).

Microsoft 2-button mouse is the default protocol.

## Remote Configuration API

When the program is started with the Remote Configuration API enabled a simple web server will be available on port 8627. With this API another program can be used to temporarily configure some settings. The changes will revert to the default values after a power cycle.

Any request will produce a JSON that may look something like this:
```
{  
   "power":true,
   "version":"1.1.1",
   "settings":{  
      "x":1.000000,
      "y":1.000000,
      "swap":false,
      "rate":7.500000
   },
   "info":{  
      "mouse":"Razer Razer DeathAdder",
      "protocol":"microsoft"
   }
}
```
If power is off, the value for `power` will be `false` and `settings` and `protocol` is not available:
```
{  
   "power":false,
   "version":"1.1.1",
   "info":{  
      "mouse":"Razer Razer DeathAdder"
   }
}
```
The value of `mouse` is `null` if there is no mouse connected.

Settings are changed with query-parameters. The following parameters are available:
```
x=number
	Change the X-multiplier
y=number
	Change the Y-multiplier
swap=boolean
	Swap the left and right button
rate=number
	Set the output rate
invert=boolean
	Invert the current Y-movement, same as setting Y-multiplier negative
reset(=boolean)
	Reset all temporary changes to the defaults, if the boolean-value is omitted it will be set to true
```

### Example requests
Disable Y-movement:
```
http://192.168.1.10:8627/?y=0
```
Multiply the X-movement by 2 and invert the Y-movement:
```
http://192.168.1.10:8627/?x=2&y=-1
```
Multiply the X- and Y-movement by 1.5 and swap left and right mouse buttons:
```
http://192.168.1.10:8627/?x=1.5&y=1.5&swap=true
```
Swap left and right mouse buttons back:
```
http://192.168.1.10:8627/?swap=false
```
Reset to default values:
```
http://192.168.1.10:8627/?reset
```

An Android app for remote configuration is available [here](https://github.com/mborjesson/USB-Mouse-to-Serial-Configuration-Android).

## Installation

Connect a Raspberry Pi to a computer over the serial ports using a null modem cable.
Connect a USB mouse to the Raspberry Pi.
For the best experience it is recommended to set the polling rate of the USB mouse to 1000hz. This can be done by adding "usbhid.mousepoll=1" (without quotes) at the end of /boot/cmdline.txt so it looks something like this:

```
...fsck.repair=yes rootwait usbhid.mousepoll=1
```
A reboot is required for the change to take effect.

Verify that it worked:

```
cat /sys/module/usbhid/parameters/mousepoll 
1
```
Then install dependencies:

```
sudo apt install libevdev-dev
```
And finally compile and install the program:

```
make
sudo make install
```

## Running

The program should be run as root.

The following parameters are available:

```
-o, --output device
	Serial device to use as output.
	If not set it will use /dev/ttyUSB0.
-i, --input device
	USB mouse device to use as input.
	It is recommended to not set this and let the program find a mouse automatically.
	If a mouse can’t be found or if the computer has more than one mouse connected use
	this to manually select one. The device is one of /dev/input/event*.
-p, --protocol protocol
	The protocol to use. One of microsoft, logitech, wheel or mousesystems (see
	Mouse Protocols above). The default is microsoft.
-r, --rate rate
	The rate to write to the serial output device in milliseconds.
	This value can be used to tweak how often the program should send data to the computer.
	By default the rate is 7.5 milliseconds for all protocols except Mouse Systems which
	is 8.33 milliseconds (might change later).
-d, --daemon
	Run in background.
-s, --suspend
	Automatically suspend mouse when there is no power from the serial port.
	May not work on all devices.
-x multiplier / -y multiplier
	Multiply X / Y with this value.
-S, --swap
	Swap left and right mouse buttons.
-I, --invert
	Invert the value of Y-multiplier.
-c, --config
	Start the Remote Configuration API.
-P, --port port
	Set the port for the Remote Configuration API, default is 8627.
-v, --verbose
	Increase verbosity, can be used multiple times.
-V, --version
	Show version.
-h, --help
	Show usage and help.
```

### Example

```
usb_mouse_to_serial --output /dev/ttyUSB1 --protocol wheel --suspend --daemon --config
```

## DOS Drivers

Any mouse driver designed for the specified protocol should work.

### CuteMouse

CuteMouse is a modern DOS-based open source mouse driver that is compatible with this project. It can be downloaded from http://cutemouse.sourceforge.net/

## Disclaimer

This project is provided as-is, comes with no warranty and is not liable for any loss or damage to your equipment while using this program.
