/**
 * Module for local tcp session tracking for Spider {@link http://spider.io}
 * @author TincaTibo@gmail.com
 * @type {exports|module.exports}
 */

const http = require('http');
const zlib = require('zlib');
var request = require('request');
var async = require('async');
var debug = require('debug')('tcp-sessions-tracker');

var IPv4 = require('pcap/decode/ipv4');
var TCP = require('pcap/decode/tcp');

/**
 * Class to track tcp sessions
 * @param {WhispererConfig} config
 * @constructor
 */
function TcpTracker(config){
    this.sessions = new Map;
    this.updated = false;
    this.lastSentDate = 0;
    this.sessionTimeOutSec = config.tcpSessions.sessionTimeOutSec ? config.tcpSessions.sessionTimeOutSec : 120; //a session without packets for 2 minutes is deleted
    this.stats = {
        nbPacketsTracked: 0,
        nbPacketsNotTCP:0,
        nbPacketsOutsideSessions:0,
    };

    if(config.tcpSessions.delaySec){
        //Set timeout for sending sessions regularly to the server
        //If changed
        //And to remove sessions from memory when closed and sent
        this.interval_send = setInterval(function (that) {
            if(that.updated){
                that.updated = false;
                that.send();
            }
        }, config.tcpSessions.delaySec * 5000, this);
    }

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

var OPENED = 'OPENED';
var RESET = 'RESET';
var FIN = 'FIN';
var SYN = 'SYN';
var FINASK = 'FINASK';

/**
 * Adds a packet in a TcpSession to associate them together.
 * Not possible to do it with performance on the server side with distributed processing
 * @param {PcapPacket} packet
 * @param {string} packetId
 */
TcpTracker.prototype.trackPacket = function (packet, packetId) {

    this.stats.nbPacketsTracked++;

    //only for TCP / IPV4 for now
    if (packet.payload.payload instanceof IPv4 && packet.payload.payload.payload instanceof TCP) {
        var ip  = packet.payload.payload;
        var tcp = ip.payload;

        var srcIp = ip.saddr.addr.join('.');
        var dstIp = ip.daddr.addr.join('.');

        var id = `${srcIp}:${tcp.sport}-${dstIp}:${tcp.dport}`;
        var di = `${dstIp}:${tcp.dport}-${srcIp}:${tcp.sport}`;

        if (tcp.flags.syn && !tcp.flags.fin){ //initiating tcp connection : SYN flag -- not allowed with FIN
            if (this.sessions.has(id)){ //more than one request SYN: com with pb -- what should we do ?
                this.sessions.get(id).outPackets.push(packetId);
            }
            else if (this.sessions.has(di)){ //response SYN
                this.sessions.get(di).inPackets.push(packetId);
                this.sessions.get(di).state = OPENED;
                this.sessions.get(di).minInSeq = tcp.seqno; //to avoid lost packets arriving late
            }
            else { //request SYN ==> create session
                this.sessions.set(id, new TcpSession());
                this.sessions.get(id).outPackets.push(packetId);
                this.sessions.get(id).state = SYN;
                this.sessions.get(id).minOutSeq = tcp.seqno;
            }
        }
        else if(tcp.flags.rst){ //Reset connection (close) //TODO: can we have RST with other?
            if (this.sessions.has(id)){
                this.sessions.get(id).outPackets.push(packetId);
                this.sessions.get(id).state = RESET;
            }
            else if (this.sessions.has(di)){
                this.sessions.get(di).inPackets.push(packetId);
                this.sessions.get(di).state = RESET;
            }
            else {
                //reset on unknown connection
            }
        }
        else if(tcp.flags.fin){ //end of tcp connection : FIN flag
            if (this.sessions.has(id)){
                this.sessions.get(id).outPackets.push(packetId);
                if (this.sessions.get(id).state === FINASK){
                    this.sessions.get(id).state = FIN;
                }
                else {
                    this.sessions.get(id).state = FINASK;
                }
            }
            else if (this.sessions.has(di)){
                this.sessions.get(di).inPackets.push(packetId);
                if (this.sessions.get(di).state === FINASK){
                    this.sessions.get(di).state = FIN;
                }
                else {
                    this.sessions.get(di).state = FINASK;
                }
            }
            else {
                //fin on unknown connection
            }
        }
        else if(tcp.flags.ack){
            if (this.sessions.has(id)){ //packet on an existing session
                this.sessions.get(id).outPackets.push(packetId);
                if (this.sessions.get(id).state !== OPENED){
                    this.sessions.get(id).state = OPENED;
                }
            }
            else if (this.sessions.has(di)){ //packet on an existing session
                this.sessions.get(di).inPackets.push(packetId);
                if (this.sessions.get(di).state !== OPENED){
                    this.sessions.get(di).state = OPENED;
                }
            }
            else{ //Got a packet on a session not opened, so we create a new session
                // We guess the direction (src port > dst port)
                if (tcp.sport > tcp.dport){
                    this.sessions.set(id, new TcpSession());
                    this.sessions.get(id).outPackets.push(packetId);
                    this.sessions.get(id).state = OPENED;
                    this.sessions.get(id).minOutSeq = tcp.seqno;
                    this.sessions.get(id).minInSeq = tcp.ackno;
                }
                else {
                    this.sessions.set(di, new TcpSession());
                    this.sessions.get(di).inPackets.push(packetId);
                    this.sessions.get(di).state = OPENED;
                    this.sessions.get(di).minInSeq = tcp.seqno;
                    this.sessions.get(di).minOutSeq = tcp.ackno;
                }
            }
        }
        else if ((this.sessions.has(id) && this.sessions.get(id).minOutSeq && ( (tcp.seqno < this.sessions.get(id).minOutSeq && (Math.abs(this.sessions.get(id).minOutSeq - tcp.seqno) < Math.pow(2,31))) //if min is near 2**32-1 and packet near 0 .. packet is good
            || (tcp.seqno > this.sessions.get(id).minOutSeq && (Math.abs(this.sessions.get(id).minOutSeq - tcp.seqno) > Math.pow(2,31))))) //case min is near 0 and packet arrives near 2**32-1
            ||
            (this.sessions.has(di) && this.sessions.get(di).minInSeq && ( (tcp.seqno < this.sessions.get(di).minInSeq && (Math.abs(this.sessions.get(di).minInSeq - tcp.seqno) < Math.pow(2,31))) //if min is near 2**32-1 and packet near 0 .. packet is good
            || (tcp.seqno > this.sessions.get(di).minInSeq && (Math.abs(this.sessions.get(di).minInSeq - tcp.seqno) > Math.pow(2,31)))))) { //case min is near 0 and packet arrives near 2**32-1)
            //packet got late, is outside tcp session, ignore it
            return;
        }
        else { //any other packet for an opened session
            if (this.sessions.has(id) && this.sessions.get(id).state === OPENED){ //packet on an existing session
                this.sessions.get(id).outPackets.push(packetId);
            }
            else if (this.sessions.has(di) && this.sessions.get(id).state === OPENED){ //packet on an existing session
                this.sessions.get(di).inPackets.push(packetId);
            }
            else{
                //a packet for which we have nothing to do
            }
        }

        //If we did something on sessions
        if (this.sessions.has(id)){
            this.updated = true;
            this.sessions.get(id).lastUpdate = packet.pcap_header.tv_sec + packet.pcap_header.tv_usec/1e6;
        }
        else if (this.sessions.has(di)){
            this.updated = true;
            this.sessions.get(di).lastUpdate = packet.pcap_header.tv_sec + packet.pcap_header.tv_usec/1e6;
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

/**
 * Send sessions to server and remove oldest
 */
TcpTracker.prototype.send = function () {
    var currentDate = new Date().getTime()/1e3;
    var sessionsToSend =  {};
    var sessionsToDelete = [];

    //Detect sessions to delete
    this.sessions.forEach((session, id) => {
        if (session.state === RESET || session.state === FIN || (currentDate - session.lastUpdate > this.sessionTimeOut * 1000)){
            sessionsToDelete.push(id);
        }
        if (session.lastUpdate >= this.lastSentDate) {
            sessionsToSend[id] = {
                state: session.state,
                inPackets: session.inPackets,
                outPackets: session.outPackets,
                lastUpdate: session.lastUpdate
            };
        }
    }, this);

    debug(`Sending ${Object.keys(sessionsToSend).length} sessions out of ${this.sessions.size}.`);

    zlib.gzip(JSON.stringify(sessionsToSend), (err, zbf) => {
        if (err) {
            console.error(err);
        }
        else {
            this.options.body = zbf;
            this.options.headers['Content-Length'] = zbf.length;

            request(this.options,(err, res, body) => {
                if(err){
                    console.error(err);
                }
                else{
                    debug(`ResponseStatus: ${res.statusCode}`);
                    if(res.statusCode != 202){
                        debug(body);
                    }
                }
            });
        }
    });

    debug(`Deleting ${sessionsToDelete.length} closed sessions.`);
    //delete sessions that are closed AND sent
    sessionsToDelete.forEach((id) => {this.sessions.delete(id)}, this);
    debug(`Stats: ${this.stats.nbPacketsTracked} tracked, ${this.stats.nbPacketsNotTCP} not TCP, ${this.stats.nbPacketsOutsideSessions} not in session.`);

    this.lastSentDate = currentDate;
}

/**
 * Sessions tracked in memory. Not quite the same as the ones sent to the server.
 * @constructor
 * @private
 */
function TcpSession(){
    this.state = null;
    this.inPackets = [];
    this.outPackets = [];
    this.minInSeq = null;
    this.minOutSeq = null;
    this.lastUpdate = null;
}

module.exports = TcpTracker;