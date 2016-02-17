/**
 * Module defining packet sending logic for Whisperer {@link http://spider.io}
 * @module lib/packet-senders
 * @author TincaTibo@gmail.com
 * @type {exports|module.exports}
 */

const fs = require('fs');
const http = require('http');
const zlib = require('zlib');
var request = require('request');
var async = require('async');
var debug = require('debug')('packet-senders');

//TODO: Refactor with inheritance and 3 different files: packet-sender / websender / filesender
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
 * Object to send packets on the web to Spider server
 * @param {string} linkType - Link-type detected by libpcap and transcoded by node-pcap
 * @param {WhispererConfig} config
 * @constructor
 */
var WebSender = function (linkType, config){
    this.globalHeader = createGlobalHeader(linkType);

    //Options to export to Spider-Pack
    this.options = {
        method: 'POST',
        uri: config.packets.spiderPackURI,
        headers: {
            'Content-Type': 'application/vnd.tcpdump.pcap',
            'Content-Encoding': 'gzip'
        },
        gzip: true,
        time: true, //monitors the request
        timeout: config.packets.spiderPackTimeout //ms
    };
};

/**
 * Actually sends packets in the input buffer to Spider server,
 * while adding first the pcap header to the file
 * @param {Buffer} bf - Buffer containing pcap packets to send
 */
WebSender.prototype.send = function (bf) {
    //TODO: improve this by removing concat and sending both buffer to the zip. Perf tests needed.
    debug(`Sending ${bf.length} bytes of packets.`);

    var bfToSend = Buffer.concat([this.globalHeader,bf],this.globalHeader.length + bf.length);

    // zip
    zlib.gzip(bfToSend, (err, zbf) => {
        if (err) {
            debug(err);
        }
        else {
            this.options.body = zbf;
            this.options.headers['Content-Length'] = zbf.length;

            request(this.options,(err, res, body) => {
                if(err){
                    console.error(err);
                }
                else{
                    debug(`ResponseStatus: ${res.statusCode}`);
                    if(res.statusCode != 202){
                        debug(body);
                    }
                }
            });
        }
    });

};

/**
 * Object to save packets into local pcap files
 * @param {string} linkType - Link-type detected by libpcap and transcoded by node-pcap
 * @constructor
 */
var FileSender = function (linkType){
    this.globalHeader = createGlobalHeader(linkType);
    this.i = 0;
};

/**
 * Actually write packets to a new file,
 * while adding first the pcap header to the file
 * @param {Buffer} bf - Buffer containing pcap packets to send
 */
FileSender.prototype.send = function (bf) {
    //Export to file
    var fileName = `./logs/output-${this.i++}.pcap`;
    var globalHeader = this.globalHeader;

    fs.open(fileName, 'w', function (err,fd) {
        if (err) throw err;

        //Global header writing
        fs.write(fd, globalHeader, 0, globalHeader.length, function (err, written, buffer) {
            if (err) throw err;

            //Packets writing
            fs.write(fd, bf, 0, bf.length, written, function (err, written, buffer) {
                if (err) throw err;

                //Close file at the end of buffer
                fs.close(fd, function (err) {
                    if (err) throw err;
                    debug(`File ${fileName}: Saved!`);
                });
            });
        });
    });
};

exports.WebSender = WebSender;
exports.FileSender = FileSender;