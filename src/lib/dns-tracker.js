const Q = require('q');
const debug = require('debug')('dns-cache');
const DNSCache = require('./dns-cache');

const IPv4 = require('pcap/decode/ipv4');

class DNSTracker {
    constructor(config) {
        this.dnsCache = new DNSCache(config);
        
        //on regular intervals, get DNSCache changes
        //send the changes to Whisperer Config server
        //hostnames are used on GUI for hostname display, but can be overriden by configuration on Whisperer Config
    }

    trackIpFromPacket(packet) {
        if (packet.payload.payload instanceof IPv4){
            const ip  = packet.payload.payload;

            const srcIp = ip.saddr.addr.join('.');
            const dstIp = ip.daddr.addr.join('.');

            //add IPs to DNS Cache
            
        }
    }
}

module.exports = DNSTracker;