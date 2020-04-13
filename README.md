# usbrply

Convert a .pcap file (captured USB packets) to Python or C code that replays the captured USB commands.

Supported packet sources are:
* Linux Wireshark (via usbmon)
* Windows Wireshark (via USBPcap)

Supported output formats are:
* libusb Python (primary)
* (libusb C: fixme)
* (Linux Kernel C: fixme)
* JSON

Example applications:
* Rapidly reverse engineer and re-implement USB protocols
* Record a proprietary Windows programming sequence and replay on an embedded Linux device
* Snoop USB-serial packets

Questions? Please reach out on github or join #usbrply on Freenode IRC

Sample workflow for capturing Windows traffic and replaying traffic in Python:
* Install Wireshark. Make sure you install the USBPcap library
* Start Wireshark
* Connect USB device to computer
* Start catpure
* Start your application, do your thing, etc to generate packets
* Close application
* Stop capture
* Save capture. Save in pcap-ng format (either should work)
* Close Wireshark
* Run: "usbrply --device-hi -p my.pcapng >replay.py"
* Linux: run "python replay.py"
* Verify expected device behavior. Did an LED blink? Did you get expected data back?

Sample workflow for capturing Windows VM traffic from Linux host and replaying traffic in Python:
* Example: program a Xilinx dev board under Linux without knowing anything about the JTAG adapter USB protocol
* Linux: Install Wireshark
* Linux: Enable usbmon so Wireshark can capture USB (sudo modprobe usbmon, see http://wiki.wireshark.org/CaptureSetup/USB)
* Linux: Boot Windows VM (ie through VMWare)
* Linux: Start Wireshark. Make sure you have USB permissions (ie you may need to sudo)
* Connect USB device to computer
* Linux: use lsusb to determine which device bus is on. Try to choose a bus (port) with no other devices
* Linux: start catpure on bus from above
* Linux: attach USB device to Windows guest
* Windows: start your application, do your thing, etc to generate packets
* Linux: stop capture
* Linux: save capture. Save in pcap-ng format (either should work)
* Linux: run: "usbrply --device-hi -p my.pcapng >replay.py"
* Linux: detatch USB device from Windows guest
* Linux: run "python replay.py"
* Verify expected device behavior. Did an LED blink? Did you get expected data back?

You may need to filter out USB devices. There are two ways to do this:
* --device-hi: use the last device enumerated. This works well in most cases, including FX2 renumeration
* --device DEVICE: manually specify the USB device used. Get this from lsusb output or Wireshark view

Other useful switches:
* --rel-pkt: intended to easier allow diffing two outputs. Ex: what changed in trace for LED on vs LED off?
* --no-packet-numbers: alternative to above
* --fx2: decode common FX2 commands (ex: CPU reset)
* --range RANGE: only decode a specific packet range. Use along with Wireshark GUI or refine a previous decode
* see --help for more


# JSON output

use -j switch to output a parsing intermediate representation that should resemble original USB requests
along with associated metadata.
This can be used in more advanced applications, such as if you need to decode a complicated protocol
or convert USB output to higher level API calls.
An example can be found here: https://github.com/ProgHQ/bpmicro/blob/master/scrape.py
This example first aggregates USB packets into application specific packets, and then decodes these into API calls

