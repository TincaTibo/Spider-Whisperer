/**
 * Module defining packet sending logic to file for Whisperer {@link http://spider.io}
 * @module lib/packet-senders
 * @author TincaTibo@gmail.com
 * @type {exports|module.exports}
 */

"use strict";

const Config = require('../config/config').WhispererConfig;
const debug = require('debug')('file-packet-sender');
const PacketSender = require('./packet-sender');
const Q = require('q');
const FS = require('q-io/fs');

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
        const that = this;
        return Q.async(function * () {
            //Export to file
            const fileName = `${Config.getInstance().dumpPackets.outputPath}/output-${that.i++}.pcap`;
            const globalHeader = that.globalHeader;
            const fd = yield FS.open(fileName, 'w');

            //Global header writing
            let written = yield fd.write(globalHeader);

            //Packets writing
            yield fd.write(bf);

            //Close file at the end of buffer
            yield fd.close();
            debug(`File ${fileName}: Saved!`);
        })();
    }
}

module.exports = FileSender;