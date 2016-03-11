/**
 * Module defining packet sending logic for Whisperer {@link http://spider.io}
 * @module lib/packet-sender
 * @author TincaTibo@gmail.com
 * @type {exports|module.exports}
 */

"use strict";

/**
 * Create Pcap file header for exports
 * See: https://wiki.wireshark.org/Development/LibpcapFileFormat
 * @param {string} linkType - link-type detected by libpcap and transcoded by node-pcap
 * @returns {Buffer} - the buffers ready to be written at start of file
 */
function createGlobalHeader(linkType){
    var dataLinksTypes = {
        "LINKTYPE_NULL": 0, /* BSD loopback encapsulation */
        "LINKTYPE_ETHERNET": 1, /* Ethernet (10Mb) */
        "LINKTYPE_IEEE802_11_RADIO": 127,
        "LINKTYPE_RAW": 12,
        "LINKTYPE_LINUX_SLL": 113
    };

    var buf = new Buffer(24);        //Size of Libpcapfileformat globalheader
    buf.writeUInt32LE(0xa1b2c3d4,0); //Magicnumber for nanosecond resolution files (libpcap>1.5.0)
    buf.writeUInt16LE(2,4);          //Major version of libpcap file format. Current: 2.4
    buf.writeUInt16LE(4,6);          //Minor version
    buf.writeInt32LE(0,8);           //Timestamps are in GMT, so 0
    buf.writeUInt32LE(0,12);         //Time precision
    buf.writeUInt32LE(65535,16);     //Max size of packets
    buf.writeUInt32LE(dataLinksTypes[linkType],20); //Datalink

    return buf;
}

/**
 * Object to send packets
 * @interface
 */
class PacketSender {

    /**
     * @param {string} linkType - Link-type detected by libpcap and transcoded by node-pcap
     * @constructor
     */
    constructor(linkType){
        this.globalHeader = createGlobalHeader(linkType);
    }

    /**
     * Actually sends packets from the input buffer,
     * while adding first the pcap header to the file
     * @param {Buffer} bf - Buffer containing pcap packets to send
     */
    send(bf, callback) {}
}

module.exports = PacketSender;