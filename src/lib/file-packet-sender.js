/**
 * Module defining packet sending logic to file for Whisperer {@link http://spider.io}
 * @module lib/packet-senders
 * @author TincaTibo@gmail.com
 * @type {exports|module.exports}
 */

"use strict";

const fs = require('fs');
const Config = require('../config/config').WhispererConfig;
const debug = require('debug')('file-packet-sender');
const PacketSender = require('./packet-sender');

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
    send(bf, callback){
        //Export to file
        var fileName = `${Config.getInstance().dumpPackets.outputPath}/output-${this.i++}.pcap`;
        var globalHeader = this.globalHeader;

        fs.open(fileName, 'w', function (err,fd) {
            if (err) return callback(err);

            //Global header writing
            fs.write(fd, globalHeader, 0, globalHeader.length, function (err, written) {
                if (err) return callback(err);

                //Packets writing
                fs.write(fd, bf, 0, bf.length, written, function (err) {
                    if (err) return callback(err);

                    //Close file at the end of buffer
                    fs.close(fd, function (err) {
                        if (err) return callback(err);

                        debug(`File ${fileName}: Saved!`);
                        return callback(null);
                    });
                });
            });
        });
    }
}

module.exports = FileSender;