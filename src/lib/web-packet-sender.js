/**
 * Module defining packet sending logic for Whisperer {@link http://spider.io}
 * @module lib/packet-senders
 * @author TincaTibo@gmail.com
 * @type {exports|module.exports}
 */

"use strict";

const http = require('http');
const zlib = require('zlib');
var request = require('request');
var async = require('async');
var debug = require('debug')('web-packet-sender');
var PacketSender = require('./packet-sender');

/**
 * Object to send packets on the web to Spider server
 * @class
 */
class WebSender extends PacketSender {

    /**
     * @param {string} linkType - Link-type detected by libpcap and transcoded by node-pcap
     * @param {WhispererConfig} config
     * @constructor
     */
    constructor(linkType, config) {
        super (linkType);

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
    send (bf, callback) {
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
                        return callback(err);
                    }
                    else{
                        debug(`ResponseStatus: ${res.statusCode}`);
                        if(res.statusCode != 202){
                            debug(body);
                        }
                        return callback(null);
                    }
                });
            }
        });

    }
}

module.exports = WebSender;