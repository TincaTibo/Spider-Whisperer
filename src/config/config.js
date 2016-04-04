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
                && _.isString(source.client.capture.mode) && _.isString(source.client.capture.file) && _.isString(source.client.capture.interface)
                && _.isString(source.client.capture.filter) && _.isInteger(source.client.capture.captureBufferkB)
                && _.isString(source.client.packets.spiderPackURI) && _.isString(source.client.packets.spiderPackTimeout) && _.isInteger(source.client.packets.sendBufferSizekB)
                && _.isString(source.client.packets.sendBufferDelay)
                && _.isBoolean(source.client.dumpPackets.dumpToFile) && _.isString(source.client.dumpPackets.outputPath) && _.isInteger(source.client.dumpPackets.fileBufferSizekB)
                && _.isBoolean(source.client.dnsCache.trackIp) && _.isString(source.client.dnsCache.ttl) && _.isString(source.client.dnsCache.sendDelay)
                && _.isString(source.client.dnsCache.purgeDelay) && _.isString(source.client.dnsCache.spiderConfigURI) && _.isString(source.client.dnsCache.spiderConfigTimeout)
                && _.isBoolean(source.client.tcpSessions.track) && _.isString(source.client.tcpSessions.spiderTcpStreamsURI) && _.isString(source.client.tcpSessions.sendSessionDelay)
                && _.isString(source.client.tcpSessions.sessionTimeOut) && _.isString(source.client.tcpSessions.spiderTCPSTreamsTimeout)
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
        this.packets.spiderPackURI = null;
        this.packets.spiderPackTimeout = null;
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
        this.dnsCache.sendDelay = null;
        this.dnsCache.purgeDelay = null;
        this.dnsCache.spiderConfigURI = null;
        this.dnsCache.spiderConfigTimeout = null;

        //For sessions
        this.tcpSessions = {};
        this.tcpSessions.track = null;
        this.tcpSessions.spiderTcpStreamsURI = null;
        this.tcpSessions.sendSessionDelay = null;
        this.tcpSessions.sessionTimeOut = null;
        this.tcpSessions.spiderTCPSTreamsTimeout = null;

        _.assign(this, source.client);

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
                uri: `${spiderWhispsURI}/whisperers/${whispererId}/config/v1`,
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
