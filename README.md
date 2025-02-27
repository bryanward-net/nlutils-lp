# nlutils-lp

A command-line utility that scans for Wi-Fi networks using the 802.11 netlink API and outputs the scan results in Influx Line Protocol format.

Typically, processes that need to gather data about nearby Wi-Fi networks would do a scan using [iw](https://wireless.wiki.kernel.org/en/users/documentation/iw) and scrape its text output. However, it is generally a bad idea to try parsing another program's output if it is not designed to be consumed by other processes. The text may change with newer updates or simply by running the program on a different system. 

With **nlutils-lp**, no more scraping is needed.

This is based on [**scandump**](https://github.com/intuitibits/scandump) by Adrian Granados from Intuitibits.

## Features

## nlscan-lp

Reports 802.11 scan results including BSSID, SSID, Frequency, Channel, and RSSI

## nlassoc-lp

Coming Soon.

Reports BSSID, SSID, Frequency, Channel, and RSSI of the current association

## Installation

```shell
# Install pre-requisites
sudo apt update
sudo apt install git libnl-genl-3-dev libpcap-dev

# Download, build, and install scandump
git clone https://github.com/bryanward-net/nlutils-lp.git
cd nlutils-lp
make
sudo make install
```

## Usage

```shell
Usage: nlscan-lp <interface>
       nlscan-lp -v	Display version and exit
```

Where `<interface>` is the name of the WLAN interface (e.g. `wlan0`).  Standard output is used to output the Line Protocol data.

The command must be run as root since only privileged processes can initiate a scan.
A sudoers.d file is included to enable non-root users to run the command.

## Example

Scan for Wi-Fi networks on `wlan0`:
```console
$ sudo nlscan-lp wlan0
```
