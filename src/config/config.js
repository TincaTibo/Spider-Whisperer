/**
 * Configuration fetcher module for Whisperer
 * @author TincaTibo@gmail.com
 * @module lib/config
 */

"use strict";

const Q = require('q');

/**
 * Current config
 * @static
 * @type {WhispererConfig}
 */
var whispererConfig = null;

const INTERFACE = Symbol('INTERFACE');
const FILE = Symbol('FILE');

/**
 * Configuration fetcher for Whisperer
 * @class
 */
class WhispererConfig {
    //TODO : use moment and ISO everywhere
    constructor () {
        this.token = 'test';

        //Capture parameters
        this.capture = {};
        this.capture.mode = FILE; // INTERFACE OR FILE
        this.capture.file = '../test/test-parkeon.com2.pcap';
        this.capture.interface = 'wlan1';
        this.capture.filter = 'tcp port 80';
        this.capture.captureBufferkB = 10;

        //For packets
        this.packets = {};
        this.packets.spiderPackURI = 'http://localhost:3000/packets/v1';
        this.packets.spiderPackTimeout = 'PT2S';
        //Packet saving to Spider
        this.packets.sendBufferSizekB = 100;
        this.packets.sendBufferDelay = 'PT5S';

        //Packet saving to file
        this.dumpPackets = {};
        this.dumpPackets.dumpToFile = true;
        this.dumpPackets.fileBufferSizekB = 1000;
        this.dumpPackets.outputPath = '../logs';

        //For DNS reversal
        this.dnsCache = {};
        this.dnsCache.trackIp = true;
        this.dnsCache.ttl = 'P1D';
        this.dnsCache.sendDelay = 'PT20S';
        this.dnsCache.purgeDelay = 'PT1H';
        this.dnsCache.spiderConfigURI = 'http://localhost:3003/';
        this.dnsCache.spiderConfigTimeout = 'PT2S';

        //For sessions
        this.tcpSessions = {};
        this.tcpSessions.track = true;
        this.tcpSessions.spiderTcpStreamsURI = 'http://localhost:3001/tcp-sessions/v1';
        this.tcpSessions.sendSessionDelay = 'PT5S';
        this.tcpSessions.sessionTimeOutSec = 120;
        this.tcpSessions.spiderTCPSTreamsTimeout = 'PT2S';

        whispererConfig = this;
    }

    /**
     * Get configuration from Spider
     * @returns {WhispererConfig}
     */
    static initConfig(){
        return Q(new WhispererConfig());
    }

    /**
     * Return current instance
     * @returns {WhispererConfig}
     */
    static getInstance () {
        return whispererConfig;
    }
}

module.exports.WhispererConfig = WhispererConfig;
module.exports.INTERFACE = INTERFACE;
module.exports.FILE = FILE;
