/**
 * Sessions tracked in memory. Not quite the same as the ones sent to the server.
 * @class
 * @private
 */

"use strict";

class TcpSession{
    constructor(packetId) {
        this['@id'] = `tcp:${packetId}`;
        this['@type'] = 'sp:tcp-session';
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
        }

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
     */
    add(direction, packet, packetId, timeStamp){
        this[direction]['packets'].push({
            '@id': `pck:${packetId}`,
            tcpPayload: packet.payload.payload.payload.dataLength > 0,
            timestamp: timeStamp
        });
        this[direction]['ip'] += packet.payload.payload.headerLength;
        this[direction]['tcp'] += packet.payload.payload.payload.headerLength;
        this[direction]['payload'] += packet.payload.payload.payload.dataLength;

        this.lastTimestamp = timeStamp;
    }

    /**
     * Emptys packets array
     */
    clearPackets(){
        this.in.packets.length = 0;
        this.out.packets.length = 0;
    }
}

module.exports = TcpSession;