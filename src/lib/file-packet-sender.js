/**
 * Module defining packet sending logic to file for Whisperer {@link http://spider.io}
 * @module lib/packet-senders
 * @author TincaTibo@gmail.com
 * @type {exports|module.exports}
 */

"use strict";

const fs = require('fs');
var async = require('async');
var debug = require('debug')('file-packet-sender');
var PacketSender = require('./packet-sender');

/**
 * Object to save packets into local pcap files
 * @class
 */
class FileSender extends PacketSender{
    /**
     * @param {string} linkType - Link-type detected by libpcap and transcoded by node-pcap
     * @constructor
     */
    constructor(linkType){
        super(linkType);
        this.i = 0;
    }

    /**
     * Actually write packets to a new file,
     * while adding first the pcap header to the file
     * @param {Buffer} bf - Buffer containing pcap packets to send
     */
    send(bf){
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
    }
};

module.exports = FileSender;