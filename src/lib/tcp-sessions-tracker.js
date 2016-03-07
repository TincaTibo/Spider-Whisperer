/**
 * Module for local tcp session tracking for Spider {@link http://spider.io}
 * @author TincaTibo@gmail.com
 * @type {exports|module.exports}
 */

"use strict";

const http = require('http');
const zlib = require('zlib');
const request = require('request');
const async = require('async');
const debug = require('debug')('tcp-sessions-tracker');

const IPv4 = require('pcap/decode/ipv4');
const TCP = require('pcap/decode/tcp');

const TcpSession = require('../models/tcp-session-model');
var Config = require('../config/config');

const SYN_SENT = 'SYN_SENT';
const SYN_RECEIVED = 'SYN_RECEIVED';
const ESTABLISHED = 'ESTABLISHED';
const CLOSE_WAIT = 'CLOSE_WAIT';
const LAST_ACK = 'LAST_ACK';
const CLOSED = 'CLOSED';

const dirIn = 'in';
const dirOut = 'out';

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
            nbPacketsOutsideSessions:0,
        };
        this.maxTcpFrame = Math.pow(2,31);

        //Set timeout for sending sessions regularly to the server
        //If changed
        //And to remove sessions from memory when closed and sent
        this.interval_send = setInterval(function (that) {
            that.send();
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
            var ip  = packet.payload.payload;
            var tcp = ip.payload;

            var srcIp = ip.saddr.addr.join('.');
            var dstIp = ip.daddr.addr.join('.');

            var id = `${srcIp}:${tcp.sport}-${dstIp}:${tcp.dport}`;
            var di = `${dstIp}:${tcp.dport}-${srcIp}:${tcp.sport}`;

            var timeStamp = packet.pcap_header.tv_sec + packet.pcap_header.tv_usec/1e6;

            if (tcp.flags.syn && !tcp.flags.fin){ //initiating tcp connection : SYN flag -- not allowed with FIN
                if(!this.sessions.has(id) && !this.sessions.has(id) && !tcp.flags.ack) { //request SYN ==> create session
                    this.sessions.set(id, new TcpSession(packetId));
                    this.sessions.get(id).add(dirOut,packet,packetId, timeStamp);
                    this.sessions.get(id).state = SYN_SENT;
                    this.sessions.get(id).minOutSeq = tcp.seqno;
                    this.sessions.get(id).synTimestamp = timeStamp;
                }
                else if (this.sessions.has(di) && tcp.flags.ack){ //response SYN
                    this.sessions.get(di).add(dirIn,packet,packetId, timeStamp);
                    this.sessions.get(di).state = SYN_RECEIVED;
                    this.sessions.get(di).minInSeq = tcp.seqno; //to avoid lost packets arriving late
                    this.sessions.get(di).connectTimestamp = timeStamp;
                }
                else if (this.sessions.has(id)){ //not classic pattern, add it to session...
                    this.sessions.get(id).add(dirOut, packet, packetId, timeStamp);
                }
                else if (this.sessions.has(di)){ //not classic pattern, add it to session...
                    this.sessions.get(di).add(dirIn, packet, packetId, timeStamp);
                }
            }
            else if(tcp.flags.rst){ //Reset connection (close) //TODO: can we have RST with other?
                if (this.sessions.has(id)){
                    this.sessions.get(id).add(dirOut,packet,packetId, timeStamp);
                    this.sessions.get(id).state = CLOSED;
                }
                else if (this.sessions.has(di)){
                    this.sessions.get(di).add(dirIn,packet,packetId, timeStamp);
                    this.sessions.get(di).state = CLOSED;
                }
                else {
                    //reset on unknown connection
                }
            }
            else if(tcp.flags.fin){ //end of tcp connection : FIN flag
                if (this.sessions.has(id)){

                    this.sessions.get(id).add(dirOut,packet,packetId, timeStamp);

                    if (this.sessions.get(id).state === ESTABLISHED){
                        this.sessions.get(id).state = CLOSE_WAIT;
                    }
                    else if (this.sessions.get(id).state === CLOSE_WAIT){
                        this.sessions.get(id).state = LAST_ACK;
                    }
                }
                else if (this.sessions.has(di)){

                    this.sessions.get(di).add(dirIn,packet,packetId, timeStamp);

                    if (this.sessions.get(di).state === ESTABLISHED){
                        this.sessions.get(di).state = CLOSE_WAIT;
                    }
                    else if (this.sessions.get(di).state === CLOSE_WAIT){
                        this.sessions.get(di).state = LAST_ACK;
                    }
                }
                else {
                    //fin on unknown connection
                }
            }
            else if(tcp.flags.ack){
                if (this.sessions.has(id)){ //packet on an existing session
                    this.sessions.get(id).add(dirOut,packet,packetId, timeStamp);
                    if (this.sessions.get(id).state === SYN_RECEIVED ){
                        this.sessions.get(id).state = ESTABLISHED;
                    }
                    else if (this.sessions.get(id).state === LAST_ACK ){
                        this.sessions.get(id).state = CLOSED;
                    }
                }
                else if (this.sessions.has(di)){ //packet on an existing session
                    this.sessions.get(di).add(dirIn,packet,packetId, timeStamp);
                    if (this.sessions.get(di).state === SYN_RECEIVED){ //Should not happen in this direction
                        this.sessions.get(di).state = ESTABLISHED;
                    }
                    else if (this.sessions.get(di).state === LAST_ACK ){
                        this.sessions.get(di).state = CLOSED;
                    }
                }
                else if(tcp.payloadLength){ //Got a packet on a session not opened, so we create a new session if it got data
                    // We guess the direction (src port > dst port)
                    if (tcp.sport > tcp.dport){
                        this.sessions.set(id, new TcpSession(packetId));
                        this.sessions.get(id).add(dirOut,packet,packetId, timeStamp);
                        this.sessions.get(id).state = ESTABLISHED;
                        this.sessions.get(id).minOutSeq = tcp.seqno;
                        this.sessions.get(id).minInSeq = tcp.ackno;
                        this.sessions.get(id).missedSyn = true;
                    }
                    else {
                        this.sessions.set(di, new TcpSession(packetId));
                        this.sessions.get(di).add(dirIn,packet,packetId, timeStamp);
                        this.sessions.get(di).state = ESTABLISHED;
                        this.sessions.get(di).minInSeq = tcp.seqno;
                        this.sessions.get(di).minOutSeq = tcp.ackno;
                        this.sessions.get(di).missedSyn = true;
                    }
                }
            }
            else if ((this.sessions.has(id) && this.sessions.get(id).minOutSeq && ( (tcp.seqno < this.sessions.get(id).minOutSeq && (Math.abs(this.sessions.get(id).minOutSeq - tcp.seqno) < this.maxTcpFrame)) //if min is near 2**32-1 and packet near 0 .. packet is good
                || (tcp.seqno > this.sessions.get(id).minOutSeq && (Math.abs(this.sessions.get(id).minOutSeq - tcp.seqno) > this.maxTcpFrame)))) //case min is near 0 and packet arrives near 2**32-1
                ||
                (this.sessions.has(di) && this.sessions.get(di).minInSeq && ( (tcp.seqno < this.sessions.get(di).minInSeq && (Math.abs(this.sessions.get(di).minInSeq - tcp.seqno) < this.maxTcpFrame)) //if min is near 2**32-1 and packet near 0 .. packet is good
                || (tcp.seqno > this.sessions.get(di).minInSeq && (Math.abs(this.sessions.get(di).minInSeq - tcp.seqno) > this.maxTcpFrame))))) { //case min is near 0 and packet arrives near 2**32-1)
                //packet got late, is outside tcp session, ignore it
                return;
            }
            else { //any other packet for an opened session
                if (this.sessions.has(id) && this.sessions.get(id).state !== CLOSED){ //packet on an existing session not closed
                    this.sessions.get(id).add(dirOut,packet,packetId, timeStamp);
                }
                else if (this.sessions.has(di) && this.sessions.get(id).state !== CLOSED){ //packet on an existing session not closed
                    this.sessions.get(di).add(dirIn,packet,packetId, timeStamp);
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
        const currentDate = new Date().getTime() / 1e3;

        if (this.updated || (this.config.capture.mode === Config.INTERFACE && (currentDate - this.lastSentDate) > this.sessionTimeOutSec)) { //send only if new packets were registered or if we got to remove sessions
            this.updated = false;

            let sessionsToSend = {};
            let sessionsToDelete = [];
            let maxTimestamp = 0;


            this.sessions.forEach((session, id) => {
                //Send session updated since max timestamp processed since last sent
                if (session.lastTimestamp > this.lastSentDate) {
                    sessionsToSend[id] = session;
                }

                if(session.lastTimestamp > maxTimestamp){
                    maxTimestamp = session.lastTimestamp;
                }

                //Detect sessions to delete after send
                if (session.state === CLOSED) {
                    sessionsToDelete.push(id);
                }
                else if(this.config.capture.mode === Config.INTERFACE && ((currentDate - session.lastTimestamp) > this.sessionTimeOutSec)){
                    debug(`Session ${session['@id']} too old, closing it.`);
                    sessionsToDelete.push(id);
                }
            }, this);
            this.lastSentDate = maxTimestamp;

            if(Object.keys(sessionsToSend).length) {
                debug(`Sending ${Object.keys(sessionsToSend).length} sessions out of ${this.sessions.size}.`);

                let toSend = JSON.stringify(sessionsToSend); //serialised before giving the end back and risking modification

                debug(`Emptying packets from sent sessions.`);
                for (let id in sessionsToSend) {
                    if (this.sessions.has(id)) {
                        this.sessions.get(id).clearPackets();
                    }
                }

                debug(`Stats: ${this.stats.nbPacketsTracked} tracked, ${this.stats.nbPacketsNotTCP} not TCP, ${this.stats.nbPacketsOutsideSessions} not in session.`);

                //Sending the sessions
                zlib.gzip(toSend, (err, zbf) => {
                    if (err) {
                        console.error(err);
                    }
                    else {
                        this.options.body = zbf;
                        this.options.headers['Content-Length'] = zbf.length;

                        request(this.options, (err, res, body) => {
                            if (err) {
                                console.error(err);
                            }
                            else {
                                debug(`ResponseStatus: ${res.statusCode}`);
                                if (res.statusCode != 202) {
                                    debug(body);
                                }
                            }
                        });
                    }
                });
            }
            else{
                debug(`No session to send this time.`);
            }

            //delete sessions that are closed AND sent
            if(sessionsToDelete.length){
                debug(`Deleting ${sessionsToDelete.length} closed sessions.`);
                sessionsToDelete.forEach((id) => {
                    this.sessions.delete(id)
                }, this);
            }
        }
    }
}

module.exports = TcpTracker;