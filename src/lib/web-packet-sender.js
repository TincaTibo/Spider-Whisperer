/**
 * Module defining packet sending logic for Whisperer {@link http://spider.io}
 * @module lib/packet-senders
 * @author TincaTibo@gmail.com
 * @type {exports|module.exports}
 */

"use strict";

const http = require('http');
const zlib = require('zlib');
const request = require('../utils/requestAsPromise');
const async = require('async');
const debug = require('debug')('web-packet-sender');
const Q = require('q');
const PacketSender = require('./packet-sender');
const moment = require('moment');
const Config = require('../config/config').WhispererConfig;

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
            timeout: moment.duration(config.packets.spiderPackTimeout).asMilliseconds()
        };
    };

    /**
     * Actually sends packets in the input buffer to Spider server,
     * while adding first the pcap header to the file
     * @param {Buffer} bf - Buffer containing pcap packets to send
     */
    send (bf) {
        let that = this;
        return Q.async(function * (){
            //TODO: improve this by removing concat and sending both buffer to the zip. Perf tests needed.
            debug(`Sending ${bf.length} bytes of packets.`);

            var bfToSend = Buffer.concat([that.globalHeader,bf],that.globalHeader.length + bf.length);

            // zip
            let zbf = yield Q.nfcall(zlib.gzip, bfToSend);
                
            that.options.body = zbf;
            that.options.headers['Content-Length'] = zbf.length;
            that.options.headers['Authorization'] = `Bearer ${Config.getInstance().token}`;

            //send the request to Spider
            let res = yield request(that.options);

            debug(`ResponseStatus: ${res.response.statusCode} in ${res.response.elapsedTime}ms`);
            if(res.response.statusCode != 202){
                debug(res.body);
            }
        })();
    }
}

module.exports = WebSender;