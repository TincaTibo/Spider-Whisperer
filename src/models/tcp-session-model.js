/**
 * Sessions tracked in memory. Not quite the same as the ones sent to the server.
 * @class
 * @private
 */

"use strict";

const TcpPacket = require('./tcp-packet-model');

const TCP_STATUS = {
    SYN_SENT : 'SYN_SENT',
    SYN_RECEIVED : 'SYN_RECEIVED',
    ESTABLISHED : 'ESTABLISHED',
    CLOSE_WAIT : 'CLOSE_WAIT',
    LAST_ACK : 'LAST_ACK',
    CLOSED : 'CLOSED'
};

class TcpSession{
    constructor(packetId) {
        this['@id'] = `${packetId}`;
        this.state = null;

        this.in = {
            packets: [],
            ip: 0,
            tcp: 0,
            payload: 0
        };

        this.out = {
            packets: [],
            ip: 0,
            tcp: 0,
            payload: 0
        };

        this.minInSeq = null;
        this.minOutSeq = null;

        this.synTimestamp = null;
        this.connectTimestamp = null;
        this.lastTimestamp = null;
        this.missedSyn = false;
    }

    /**
     * Add a packet to the session
     * @param {string} direction of packet - 'in' or 'out'
     * @param {PcapPacket} packet
     * @param {string} packetId
     * @param {number} timestamp
     */
    add(direction, packet, packetId, timestamp){
        //Add packet to selection
        this[direction]['packets'].push(new TcpPacket({
            packet: packetId,
            tcpPayload: packet.payload.payload.payload.dataLength > 0,
            timestamp: timestamp
        }));

        //Increase stats counters
        this[direction]['ip'] += packet.payload.payload.headerLength;
        this[direction]['tcp'] += packet.payload.payload.payload.headerLength;
        this[direction]['payload'] += packet.payload.payload.payload.dataLength;

        //Update last timestamp of tcp session
        this.lastTimestamp = timestamp;
    }

    /**
     * Emptys packets array (called when a session is sent to TcpStreams)
     */
    clearPackets(){
        this.in.packets.length = 0;
        this.out.packets.length = 0;
    }
}

module.exports.TcpSession = TcpSession;
module.exports.TCP_STATUS = TCP_STATUS;