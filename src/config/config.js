/**
 * Configuration fetcher module for Whisperer
 * @author TincaTibo@gmail.com
 * @module lib/config
 */

"use strict";

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

    constructor () {
        this.token = 'test';

        //Capture parameters
        this.capture = {};
        this.capture.mode = INTERFACE; // INTERFACE OR FILE
        this.capture.file = '../test/test-parkeon.com.pcap';
        this.capture.interface = 'wlan0';
        this.capture.filter = 'tcp port 80';
        this.capture.captureBufferkB = 10;

        //For packets
        this.packets = {};
        this.packets.spiderPackURI = 'http://localhost:3000/packets/v1';
        this.packets.spiderPackTimeout = 2000;
        //Packet saving to Spider
        this.packets.sendBufferSizekB = 100;
        this.packets.sendBufferDelaySec = 5;

        //Packet saving to file
        this.dumpPackets = {};
        this.dumpPackets.dumpToFile = false;
        this.dumpPackets.fileBufferSizekB = 1000;

        //For sessions
        this.tcpSessions = {};
        this.tcpSessions.spiderTcpStreamsURI = 'http://localhost:3001/tcp-sessions/v1'
        this.tcpSessions.sendSessionDelaySec = 5;
        this.tcpSessions.sessionTimeOutSec = 120;

        whispererConfig = this;
    }

    /**
     * Get configuration from Spider
     * @returns {WhispererConfig}
     */
    getConfig(){
        return this;
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
