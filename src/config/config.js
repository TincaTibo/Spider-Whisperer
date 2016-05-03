/**
 * Configuration fetcher module for Whisperer
 * @author TincaTibo@gmail.com
 * @module lib/config
 */

"use strict";

const Q = require('q');
const _ = require('lodash');
const moment = require('moment');
const ursa = require('ursa');
const request = require('../utils/requestAsPromise');
const debug = require('debug')('config');

/**
 * Current config
 * @static
 * @type {WhispererConfig}
 */
var whispererConfig = null;
const EXPECTED_VERSION = "0.1";

const INTERFACE = 'INTERFACE';
const FILE = 'FILE';

/**
 * Configuration fetcher for Whisperer
 * @class
 */
class WhispererConfig {
    constructor (source, token) {
        if(!(source['@type'] === 'sp:whisperer-config' && source.version === EXPECTED_VERSION
                && _.isString(source.capture.mode) && _.isString(source.capture.file) && _.isString(source.capture.interface)
                && _.isString(source.capture.filter) && _.isInteger(source.capture.captureBufferkB)
                && _.isString(source.packets.spiderURI) && _.isString(source.packets.spiderTimeout) && _.isInteger(source.packets.sendBufferSizekB)
                && _.isString(source.packets.sendBufferDelay)
                && _.isBoolean(source.dumpPackets.dumpToFile) && _.isString(source.dumpPackets.outputPath) && _.isInteger(source.dumpPackets.fileBufferSizekB)
                && _.isBoolean(source.dnsCache.trackIp) && _.isString(source.dnsCache.ttl) && _.isString(source.dnsCache.sendFullDelay)
                && _.isString(source.dnsCache.sendUpdateDelay)
                && _.isString(source.dnsCache.purgeDelay) && _.isString(source.dnsCache.spiderURI) && _.isString(source.dnsCache.spiderTimeout)
                && _.isBoolean(source.tcpSessions.track) && _.isString(source.tcpSessions.spiderURI) && _.isString(source.tcpSessions.sendSessionDelay)
                && _.isString(source.tcpSessions.sessionTimeOut) && _.isString(source.tcpSessions.spiderTimeout)
            )){
            throw new Error('The provided configuration is not valid.');
        }

        this.whisperer = null;

        //Capture parameters
        this.capture = {};
        this.capture.mode = null;
        this.capture.file = null;
        this.capture.interface = null;
        this.capture.filter = null;
        this.capture.captureBufferkB = null;

        //For packets
        this.packets = {};
        this.packets.spiderURI = null;
        this.packets.spiderTimeout = null;
        //Packet saving to Spider
        this.packets.sendBufferSizekB = null;
        this.packets.sendBufferDelay = null;

        //Packet saving to file
        this.dumpPackets = {};
        this.dumpPackets.dumpToFile = null;
        this.dumpPackets.fileBufferSizekB = null;
        this.dumpPackets.outputPath = null;

        //For DNS reversal
        this.dnsCache = {};
        this.dnsCache.trackIp = null;
        this.dnsCache.ttl = null;
        this.dnsCache.sendUpdateDelay = null;
        this.dnsCache.sendFullDelay = null;
        this.dnsCache.purgeDelay = null;
        this.dnsCache.spiderURI = null;
        this.dnsCache.spiderTimeout = null;

        //For sessions
        this.tcpSessions = {};
        this.tcpSessions.track = null;
        this.tcpSessions.spiderURI = null;
        this.tcpSessions.spiderTimeout = null;
        this.tcpSessions.sendSessionDelay = null;
        this.tcpSessions.sessionTimeOut = null;

        _.assign(this, source);

        this.token = token;

        whispererConfig = this;
    }

    /**
     * Get configuration from Spider
     * @returns {WhispererConfig}
     */
    static initConfig(spiderWhispsURI, whispererId, privatePem){
        return Q.async(function * (){
            const timeStamp = moment().toISOString();
            const info = {
                timeStamp: timeStamp,
                whispererId: whispererId
            };
            const privKey = ursa.createPrivateKey(privatePem);
            const signature = privKey.hashAndSign('sha256', JSON.stringify(info), 'utf8', 'base64');

            const options = {
                method: 'GET',
                uri: `${spiderWhispsURI}/whisperers/${whispererId}/config/v1?view=client`,
                headers: {
                    'Accept': 'application/ld+json',
                    'Accept-Encoding': 'gzip',
                    'Spider-TimeStamp': timeStamp,
                    'Spider-Signature': signature
                },
                gzip: true,
                json: true,
                time: true, //monitors the request
                timeout: 2000 //ms
            };

            let res = yield request(options);
            debug(`Getting configuration: ResponseStatus: ${res.response.statusCode} in ${res.response.elapsedTime}ms.`);
            if (res.response.statusCode !== 200) {
                debug(res.body);
            }

            return new WhispererConfig(res.body, res.response.headers['spider-token']);
        })();
    }

    /**
     * Return current instance
     * @returns {WhispererConfig}
     */
    static getInstance() {
        return whispererConfig;
    }
}

module.exports.WhispererConfig = WhispererConfig;
module.exports.INTERFACE = INTERFACE;
module.exports.FILE = FILE;
