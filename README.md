# Spider



Dependencies:
For node-pcap: g++, libcap-dev
Install node-pcap directly by "npm install https://github.com/mranney/node_pcap.git"


We'll be able to accelerate things by not splitting packets and accepting many packets at once since we'll send many.
=> specific use of node-pcap => change code

-----
Modif in node-pcap:
- stats is not supported on file / offline mode
- don't close readWatcher on file / offline mode