/**
 * Module for buffering packet output
 * @author TincaTibo@gmail.com
 * @module lib/buffered-output
 */

"use strict";

const Config = require ('./../config/config').WhispererConfig;
const debug = require ('debug')('buffered-output');

/**
 * A buffer to bufferize output of pcap packets before sending to {@link BufferedOutput.sender} when buffer is bound to be full
 * @class
 */
class BufferedOutput {

    /**
     * Create a buffer to bufferize output of pcap packets before sending to {@link BufferedOutput.sender} when buffer is bound to be full
     * @param {PacketSender} sender
     * @param {{sizeKB : ?number, delaySec : number}} options
     * @constructor
     */
    constructor(sender, options){
        var sizeKB = options.sizeKB ? options.sizeKB : 100;

        this.buf = new Buffer(sizeKB * 1024);
        this.sender = sender;
        this.bytes = 0;
        this.item = 0;
        this.firstPacketTimestamp = null;

        if(options.delaySec){
            //Set timeout for sending buffer if not enough packets (but still some)
            setInterval(function (that) {
                if(that.bytes){
                    that.send(callbackSend);
                }
            }, options.delaySec * 1000, this);
        }
    }

    /**
     * Actually flush the buffer to the {@link BufferedOutput.sender}
     */
    send(callback){
        if(this.bytes) {
            this.sender.send(new Buffer(this.buf.slice(0, this.bytes)),callback);
            this.bytes = 0;
            this.item = 0;
            this.firstPacketTimestamp = '';
        }
    }

    /**
     * Add a packet to the buffer for sending (later)
     * @param {Buffer} raw_packet - raw node-pcap packet
     * @param {PcapPacket} packet - decoded packet
     * @returns {string} - packet id to send to link in tcp-session and send to Spider
     */
    add(raw_packet, packet){
        //Get packet size
        var psize = raw_packet.header.readUInt32LE(8, true);

        //If adding it to buffer would get an overflow, send buffer and clear buffer
        if(this.bytes + psize + raw_packet.header.length > this.buf.length){
            this.send(callbackSend);
        }

        //Add to buffer
        raw_packet.header.copy(this.buf, this.bytes);
        this.bytes += raw_packet.header.length;

        raw_packet.buf.copy(this.buf, this.bytes, 0, psize);
        this.bytes += psize;

        this.item++;

        if(packet && this.item === 1){
            this.firstPacketTimestamp = packet.pcap_header.tv_sec + packet.pcap_header.tv_usec/1e6;
        }

        return `${Config.getInstance().token}.${this.firstPacketTimestamp}.${this.item}`;
    }
}

function callbackSend(err){
    if (err) {
        debug(`Error while sending packets:`);
        console.error(err);
    }
}




module.exports = BufferedOutput;