/**
 * Model Packets stored in Pack
 * @type {etag|exports|module.exports}
 */

"use strict";

var _ = require('lodash');

class TcpPacket {
    /**
     * Initialize the Packet resource
     * @param {Object} resource
     * @constructor
     */
    constructor(source) {
        this.packet = null; //link to packet in Pack
        this.tcpPayload = null; //if the packet has a tcp payload or not
        this.timestamp = null; //timestamp of the packet

        _.assign(this, source);
    }
}

module.exports = TcpPacket;


