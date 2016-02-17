/**
 * Configuration fetcher module for Whisperer
 * @author TincaTibo@gmail.com
 * @module lib/config
 */

"use strict";

/**
 * Configuration fetcher for Whisperer
 * @type {WhispererConfig}
 */
var WhispererConfig = function() {
    //Capture parameters
    this.capture = {};
    this.capture.interface = 'wlan0';
    this.capture.filter = 'tcp port 80';
    this.capture.captureBufferkB = 10;

    //For packets
    this.packets = {};
    this.packets.spiderPackURI = 'http://localhost:3000/packets/v1';
    this.packets.spiderPackTimeout = 2000
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
    this.tcpSessions.sessionTimeOutSec = 120
}

/**
 * Get configuration from Spider
 * @returns {WhispererConfig}
 */
WhispererConfig.prototype.getConfig = function(){
    return this;
}

module.exports = WhispererConfig;