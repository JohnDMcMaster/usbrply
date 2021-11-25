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

# Linux installation

```
# Do one of these
# Easier to setup, but slower
sudo pip install python-pcapng
# Much faster, but no longer maintained
sudo apt-get install -y python-libpcap
git clone https://github.com/JohnDMcMaster/usbrply.git
cd usbrply
sudo python setup.py install
```

# Windows installation

There is probably an easier way to do this but this is what I got to work. Tested on Windows 7 x64

Setup python and pip
 * Get the latest Python 3 release (https://www.python.org/downloads/)
 * I used Python 3.7.8 (Windows x86-64 executable installer)
 * Keep default setup options (in particular this will install pip)

Install libusb1
* pip install libusb1

Install usb drivers
* Some USB drivers won't replay. You need to switch their USB drivers to WinUSB. You can use Zadig to switch between USB libraries for a single device.
* https://zadig.akeo.ie/
* Run Zadig
* Click on **Options** then **List all devices** then select the USB device that doesn't replay properly and **Replace Driver** with WinUSB


Install
* Open a command prompt
  * Default should be your home dir (ex: C:\Users\mcmaster)
* python -m venv usbrply
* usbrply\Scripts\activate.bat
* pip install usbrply

Test
* If not still in venv (prompt like "(usbrply)" ): usbrply/Scripts/activate.bat
* python usbrply\Scripts\usbrply -h
  * You should get a help message
* Download and place in your home dir: https://github.com/JohnDMcMaster/usbrply-test/raw/master/win1.pcapng
* python usrply\Scripts\usbrply win1.pcapng
  * You should see python code that will reproduce the .pcap file commands

# Sample workflows

Sample workflow for capturing Windows traffic and replaying traffic in Python:
* Install Wireshark. Make sure you install the USBPcap library
* Start Wireshark
* Connect USB device to computer
* Select which USB device you want to capture by clicking on the tiny blue cogwheel and checking the box next to the USB device you want to capture ![usbPcap](usbPcap.png)
* Double click on the USBPcap to start the capture
* Start your application, do your thing, etc to generate packets
* Close application
* Stop capture
* Save capture. Save in pcap-ng format (either should work)
* Close Wireshark
* Run: "usbrply --wrapper --device-hi -p my.pcapng >replay.py"
* Assuming your usb device is connected to the computer, go to "Device manager", find your device, right click on it, select "Properties", go to "Details" tab, select "Hardware IDs" from the drop-down, and you will find an entry of a form: HID\VID_046D&PID_C05A For this example the vid is 0x046D and the pid is 0xC05A
* Scroll down to the bottom of replay.py and edit the following line:
*         if (vid, pid) == (**0x0000**, **0x0000**):
* Example edited line:
*         if (vid, pid) == (**0x046D**, **0xC05A**):    
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

# Version history

v0.0.0
  * Crusty C++ program

v0.0.1
  * Crusty python program

v1.0.0
  * Separate parsing from printing
  * Windows data source officially supported

v2.0.0
  * JSON: packn moved to new "submit" and "complete" entries
  * JSON now has raw urb structures (added to submit/complete)
  * python3 support
  * libpcapng support

v2.0.1
  * Fix packaging issues

v2.1.0
  * python2 support officially removed
  * VID/PID filter fixed
  * Windows pip install instructions
  * Linux: basic interrupt support
  * General interrupt cleanup / fixes
  * Better logging for dropped packets
  * --no-packet-numbers: line numbers line up vs --packet-numbers

v2.1.1
  * Fix pip README

# JSON output

use -j switch to output a parsing intermediate representation that should resemble original USB requests
along with associated metadata.
This can be used in more advanced applications, such as if you need to decode a complicated protocol
or convert USB output to higher level API calls.
An example can be found here: https://github.com/ProgHQ/bpmicro/blob/master/scrape.py
This example first aggregates USB packets into application specific packets, and then decodes these into API calls


# USB serial decoder

usbrply-serial supported adapters:
  * FT2232C: data rx/tx

TODO: write doc

