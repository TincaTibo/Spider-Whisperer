/**
 * Module for local tcp session tracking for Spider {@link http://spider.io}
 * @author TincaTibo@gmail.com
 * @type {exports|module.exports}
 */

"use strict";

const http = require('http');
const zlib = require('zlib');
const request = require('../utils/requestAsPromise');
const debug = require('debug')('tcp-sessions-tracker');
const Q = require('q');

const IPv4 = require('pcap/decode/ipv4');
const TCP = require('pcap/decode/tcp');

const TcpSession = require('../models/tcp-session-model').TcpSession;
const TCP_STATUS = require('../models/tcp-session-model').TCP_STATUS;
const Config = require('../config/config');

const DIR_IN = 'in';
const DIR_OUT = 'out';
const MAX_TCP_FRAME = Math.pow(2,31);

/**
 * Class to track tcp sessions
 * @class
 */
class TcpTracker{
    /**
     * @param {WhispererConfig} config
     * @constructor
     */
    constructor(config){
        this.config = config;
        this.sessions = new Map;
        this.updated = false;
        this.lastSentDate = 0;
        this.sessionTimeOutSec = config.tcpSessions.sessionTimeOutSec ? config.tcpSessions.sessionTimeOutSec : 120; //a session without packets for 2 minutes is deleted
        this.stats = {
            nbPacketsTracked: 0,
            nbPacketsNotTCP:0,
            nbPacketsOutsideSessions:0
        };

        //Set timeout for sending sessions regularly to the server
        //If changed
        //And to remove sessions from memory when closed and sent
        setInterval(that => {
            that.send().fail(err => {
                debug(`Error while sending sessions: ${err.message}`);
                console.error(err);
            });
        }, config.tcpSessions.sendSessionDelaySec * 1000, this);

        //Options to export to Spider-Tcp
        this.options = {
            method: 'POST',
            uri: config.tcpSessions.spiderTcpStreamsURI,
            headers: {
                'Content-Type': 'application/json',
                'Content-Encoding': 'gzip'
            },
            gzip: true,
            time: true, //monitors the request
            timeout: config.tcpSessions.spiderPackTimeout //ms
        };
    }

    /**
     * Adds a packet in a TcpSession to associate them together.
     * Not possible to do it with performance on the server side with distributed processing
     * @param {PcapPacket} packet
     * @param {string} packetId
     */
    trackPacket(packet, packetId) {

        this.stats.nbPacketsTracked++;

        //only for TCP / IPV4 for now
        if (packet.payload.payload instanceof IPv4 && packet.payload.payload.payload instanceof TCP) {
            const ip  = packet.payload.payload;
            const tcp = ip.payload;

            const srcIp = ip.saddr.addr.join('.');
            const dstIp = ip.daddr.addr.join('.');

            const id = `${srcIp}:${tcp.sport}-${dstIp}:${tcp.dport}`;
            const di = `${dstIp}:${tcp.dport}-${srcIp}:${tcp.sport}`;

            const timeStamp = packet.pcap_header.tv_sec + packet.pcap_header.tv_usec/1e6;

            if (tcp.flags.syn && !tcp.flags.fin){ //initiating tcp connection : SYN flag -- not allowed with FIN
                if(!this.sessions.has(id) && !this.sessions.has(id) && !tcp.flags.ack) { //request SYN ==> create session
                    this.sessions.set(id, new TcpSession(packetId));
                    this.sessions.get(id).add(DIR_OUT,packet,packetId, timeStamp);
                    this.sessions.get(id).state = TCP_STATUS.SYN_SENT;
                    this.sessions.get(id).minOutSeq = tcp.seqno;
                    this.sessions.get(id).synTimestamp = timeStamp;
                }
                else if (this.sessions.has(di) && tcp.flags.ack){ //response SYN
                    this.sessions.get(di).add(DIR_IN,packet,packetId, timeStamp);
                    this.sessions.get(di).state = TCP_STATUS.SYN_RECEIVED;
                    this.sessions.get(di).minInSeq = tcp.seqno; //to avoid lost packets arriving late
                    this.sessions.get(di).connectTimestamp = timeStamp;
                }
                else if (this.sessions.has(id)){ //not classic pattern, add it to session...
                    this.sessions.get(id).add(DIR_OUT, packet, packetId, timeStamp);
                }
                else if (this.sessions.has(di)){ //not classic pattern, add it to session...
                    this.sessions.get(di).add(DIR_IN, packet, packetId, timeStamp);
                }
            }
            else if(tcp.flags.rst){ //Reset connection (close)
                if (this.sessions.has(id)){
                    this.sessions.get(id).add(DIR_OUT,packet,packetId, timeStamp);
                    this.sessions.get(id).state = TCP_STATUS.CLOSED;
                }
                else if (this.sessions.has(di)){
                    this.sessions.get(di).add(DIR_IN,packet,packetId, timeStamp);
                    this.sessions.get(di).state = TCP_STATUS.CLOSED;
                }
                else {
                    //reset on unknown connection
                }
            }
            else if(tcp.flags.fin){ //end of tcp connection : FIN flag
                if (this.sessions.has(id)){

                    this.sessions.get(id).add(DIR_OUT,packet,packetId, timeStamp);

                    if (this.sessions.get(id).state === TCP_STATUS.ESTABLISHED){
                        this.sessions.get(id).state = TCP_STATUS.CLOSE_WAIT;
                    }
                    else if (this.sessions.get(id).state === TCP_STATUS.CLOSE_WAIT){
                        this.sessions.get(id).state = TCP_STATUS.LAST_ACK;
                    }
                }
                else if (this.sessions.has(di)){

                    this.sessions.get(di).add(DIR_IN,packet,packetId, timeStamp);

                    if (this.sessions.get(di).state === TCP_STATUS.ESTABLISHED){
                        this.sessions.get(di).state = TCP_STATUS.CLOSE_WAIT;
                    }
                    else if (this.sessions.get(di).state === TCP_STATUS.CLOSE_WAIT){
                        this.sessions.get(di).state = TCP_STATUS.LAST_ACK;
                    }
                }
                else {
                    //fin on unknown connection
                }
            }
            else if(tcp.flags.ack){
                if (this.sessions.has(id)){ //packet on an existing session
                    this.sessions.get(id).add(DIR_OUT,packet,packetId, timeStamp);
                    if (this.sessions.get(id).state === TCP_STATUS.SYN_RECEIVED ){
                        this.sessions.get(id).state = TCP_STATUS.ESTABLISHED;
                    }
                    else if (this.sessions.get(id).state === TCP_STATUS.LAST_ACK ){
                        this.sessions.get(id).state = TCP_STATUS.CLOSED;
                    }
                }
                else if (this.sessions.has(di)){ //packet on an existing session
                    this.sessions.get(di).add(DIR_IN,packet,packetId, timeStamp);
                    if (this.sessions.get(di).state === TCP_STATUS.SYN_RECEIVED){ //Should not happen in this direction
                        this.sessions.get(di).state = TCP_STATUS.ESTABLISHED;
                    }
                    else if (this.sessions.get(di).state === TCP_STATUS.LAST_ACK ){
                        this.sessions.get(di).state = TCP_STATUS.CLOSED;
                    }
                }
                else if(tcp.payloadLength){ //Got a packet on a session not opened, so we create a new session if it got data
                    // We guess the direction (src port > dst port)
                    if (tcp.sport > tcp.dport){
                        this.sessions.set(id, new TcpSession(packetId));
                        this.sessions.get(id).add(DIR_OUT,packet,packetId, timeStamp);
                        this.sessions.get(id).state = TCP_STATUS.ESTABLISHED;
                        this.sessions.get(id).minOutSeq = tcp.seqno;
                        this.sessions.get(id).minInSeq = tcp.ackno;
                        this.sessions.get(id).missedSyn = true;
                    }
                    else {
                        this.sessions.set(di, new TcpSession(packetId));
                        this.sessions.get(di).add(DIR_IN,packet,packetId, timeStamp);
                        this.sessions.get(di).state = TCP_STATUS.ESTABLISHED;
                        this.sessions.get(di).minInSeq = tcp.seqno;
                        this.sessions.get(di).minOutSeq = tcp.ackno;
                        this.sessions.get(di).missedSyn = true;
                    }
                }
            }
            else if ((this.sessions.has(id) && this.sessions.get(id).minOutSeq && ( (tcp.seqno < this.sessions.get(id).minOutSeq && (Math.abs(this.sessions.get(id).minOutSeq - tcp.seqno) < MAX_TCP_FRAME)) //if min is near 2**32-1 and packet near 0 .. packet is good
                || (tcp.seqno > this.sessions.get(id).minOutSeq && (Math.abs(this.sessions.get(id).minOutSeq - tcp.seqno) > MAX_TCP_FRAME)))) //case min is near 0 and packet arrives near 2**32-1
                ||
                (this.sessions.has(di) && this.sessions.get(di).minInSeq && ( (tcp.seqno < this.sessions.get(di).minInSeq && (Math.abs(this.sessions.get(di).minInSeq - tcp.seqno) < MAX_TCP_FRAME)) //if min is near 2**32-1 and packet near 0 .. packet is good
                || (tcp.seqno > this.sessions.get(di).minInSeq && (Math.abs(this.sessions.get(di).minInSeq - tcp.seqno) > MAX_TCP_FRAME))))) { //case min is near 0 and packet arrives near 2**32-1)
                //packet got late, is outside tcp session, ignore it
                return;
            }
            else { //any other packet for an opened session
                if (this.sessions.has(id) && this.sessions.get(id).state !== TCP_STATUS.CLOSED){ //packet on an existing session not closed
                    this.sessions.get(id).add(DIR_OUT,packet,packetId, timeStamp);
                }
                else if (this.sessions.has(di) && this.sessions.get(id).state !== TCP_STATUS.CLOSED){ //packet on an existing session not closed
                    this.sessions.get(di).add(DIR_IN,packet,packetId, timeStamp);
                }
                else{
                    //a packet for which we have nothing to do
                }
            }

            //If we did something on sessions
            if (this.sessions.has(id)){
                this.updated = true;
            }
            else if (this.sessions.has(di)){
                this.updated = true;
            }
            else {
                this.stats.nbPacketsOutsideSessions++;
            }
        }
        else {
            //ignore any non IPv4 TCP packets
            this.stats.nbPacketsNotTCP++;
        }
    }

    /**CLOSE_WAIT
     * Send sessions to server and remove oldest
     */
    send() {
        const that = this;
        return Q.async(function * (){
            const currentDate = new Date().getTime() / 1e3;

            if (that.updated || (that.config.capture.mode === Config.INTERFACE && (currentDate - that.lastSentDate) > that.sessionTimeOutSec)) { //send only if new packets were registered or if we got to remove sessions
                that.updated = false;

                let sessionsToSend = {};
                let sessionsToDelete = [];
                let maxTimestamp = 0;


                that.sessions.forEach((session, id) => {
                    //Send session updated since max timestamp processed since last sent
                    if (session.lastTimestamp > that.lastSentDate) {
                        sessionsToSend[id] = session;
                    }

                    if(session.lastTimestamp > maxTimestamp){
                        maxTimestamp = session.lastTimestamp;
                    }

                    //Detect sessions to delete after send
                    if (session.state === TCP_STATUS.CLOSED) {
                        sessionsToDelete.push(id);
                    }
                    else if(that.config.capture.mode === Config.INTERFACE && ((currentDate - session.lastTimestamp) > that.sessionTimeOutSec)){
                        debug(`Session ${session['@id']} too old, closing it.`);
                        sessionsToDelete.push(id);
                    }
                }, that);
                that.lastSentDate = maxTimestamp;
                
                if(Object.keys(sessionsToSend).length) {
                    debug(`Sending ${Object.keys(sessionsToSend).length} sessions out of ${that.sessions.size}.`);

                    let toSend = JSON.stringify(sessionsToSend); //serialised before giving the end back and risking modification

                    debug(`Emptying packets from sent sessions.`);
                    for (let id in sessionsToSend) {
                        if (that.sessions.has(id)) {
                            that.sessions.get(id).clearPackets();
                        }
                    }

                    debug(`Stats: ${that.stats.nbPacketsTracked} tracked, ${that.stats.nbPacketsNotTCP} not TCP, ${that.stats.nbPacketsOutsideSessions} not in session.`);

                    //Sending the sessions
                    const zbf = yield Q.nfcall(zlib.gzip,toSend);

                    that.options.body = zbf;
                    that.options.headers['Content-Length'] = zbf.length;

                    const res = yield request(that.options);

                    debug(`ResponseStatus: ${res.response.statusCode}`);
                    if (res.response.statusCode != 202) {
                        debug(res.body);
                    }
                }
                else{
                    debug(`No session to send this time.`);
                }

                //delete sessions that are closed AND sent
                if(sessionsToDelete.length){
                    debug(`Deleting ${sessionsToDelete.length} closed sessions.`);
                    sessionsToDelete.forEach((id) => {
                        that.sessions.delete(id)
                    }, that);
                }
            }
        })();
    }
}

module.exports = TcpTracker;