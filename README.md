# RThatDissector

wireshark dissector for RTH DSA traffic


## install
* install wireshark requirements first: https://www.wireshark.org/docs/wsdg_html_chunked/ChapterSetup.html#ChSetupUNIX

```sh
mkdir build
cd build
cmake ..
make
sudo make install

```

## function
* enables the decoding if the InnoRoute DSA tag
* packets sniffet on the eth0 interface if the RealtimePI include a special DSA tag with usefull information:
	* timestamps
	* in/output ports of the RealtimeHAT
	* TAS/QCI status information
	
## example application
* show all packets which are captured per QCI-phase
