# README #

### BLE Profiler ###

BLE Profiler is a Node.js tool for profiling a Bluetooth Low Energy peripheral, built on top of a modified version of the [BLE central emulator by Sandeep Mistry](https://github.com/sandeepmistry/noble).
It enumerates the services/characteristics that are exposed by a device and, where possible, tags the level of protection applied to each service/characteristic.

The tool also offers the functionality to perform a rudimentary "dictionary attack" against the device PIN, by performing repeated pairing attempts with different PIN values.

## Prerequisites

Install Node.js

### Linux

 * Kernel version 3.6 or above
 * ```libbluetooth-dev```
 
#### Ubuntu/Debian/Raspbian

```sh
sudo apt-get install bluetooth bluez libbluetooth-dev libudev-dev
```

### Windows

[node-gyp requirements for Windows](https://github.com/TooTallNate/node-gyp#installation)

Install the required tools and configurations using Microsoft's [windows-build-tools](https://github.com/felixrieseberg/windows-build-tools) from an elevated PowerShell or cmd.exe (run as Administrator).

```cmd
npm install --global --production windows-build-tools
```

[node-bluetooth-hci-socket prerequisites](https://github.com/sandeepmistry/node-bluetooth-hci-socket#windows)
 * Compatible Bluetooth 4.0 USB adapter
 * [WinUSB](https://msdn.microsoft.com/en-ca/library/windows/hardware/ff540196(v=vs.85).aspx) driver setup for Bluetooth 4.0 USB adapter, using [Zadig tool](http://zadig.akeo.ie/)


## Install and Usage
Download the project and then navigate to /app/external/noble/ and run
```sh 
npm install
```

### On Linux
Make sure the ```bluetoothd``` service is not running, by typing
```sh
sudo systemctl stop bluetooth
```

You will then need to manually bring the HCI interface back up again. 
Assuming, hci0:
```sh
sudo hciconfig hci0 up
```

Start the tool from within the project folder:
```sh 
sudo node index
```

### On Windows
From within the project folder:
```cmd 
node index
```

### To check security for different access types
The switches "-r", "-w", and "-n" are used to check Read, Write, and Notify access respectively. If no parameter is specified, then only Read access is checked.
e.g., if you would like to check Write security, then use:
```cmd 
node index -w
```

### To check all characteristics
By default, the code will only check those characteristics that have the relevant access type in their properties lists. That is, if we consider Reads, it will only check Reads for characteristics that have the Read property set. The "-a" switch can be used to perform the check for all characteristics.
e.g., to check Read access for all characteristics:
```cmd 
node index -r -a
```

e.g., to check Read and Write for all characteristics, use:
```cmd 
node index -r -w -a
```

### Passkey options
Use the ```-p``` flag to work with different passkey options. <br />
```-p <PIN>``` allows the user to provide a static PIN during code execution. Works for devices with fixed PINs. <br />
```-p u``` prompts the user to input a PIN via the console during runtime. Applicable for devices that generate dynamic PINs. <br />
```-p d``` performs a dictionary "attack" to try and find the PIN. Useful for identifying weak static PINs (although, any static PIN is inadvisable).

### Output options
By default, the tool generates a timestamped JSON file. If a specific name is required, it can be specified with the ```-o``` flag. Do not specify a file extension.
```-o <outputfilename>```

## Troubleshooting
If the code gets stuck after "Connected to xx:xx:... ", or if it disconnects immediately after connecting, it probably means that the system has stored some previous pairing information for the device. On Windows, delete or "forget" the pairing. On Linux, try unpairing using
```sh
bt-device -r xx:xx:xx:xx:xx:xx
```
where xx:xx:xx:xx:xx:xx is the MAC address of the peripheral.

You can double-check this by running
```sh
sudo ls /var/lib/bluetooth/YY:YY:YY:YY:YY:YY
```
Here YY:YY:YY:YY:YY:YY is the MAC address of the HCI interface on the test machine. There should be no file or folder named xx:xx:xx:xx:xx:xx (where again xx:xx:xx:xx:xx:xx is the MAC address of the peripheral).


# Disclaimer #
This script, especially when used with the -w switch, may brick or otherwise render unusable the test device. We accept no responsibility if this should occur. Please understand the risks before running the script.

Only use the script on devices that belong to you!
