#!/usr/bin/env node
/**
 * Created by TincaTibo on 30/01/16.
 * @author TincaTibo@gmail.com
 * @version 0.1
 */
"use strict";

const pcap = require('pcap');
const debug = require('debug')('whisperer');
const BufferedOutput = require('./lib/buffered-output');
const WebSender = require('./lib/web-packet-sender');
const FileSender = require('./lib/file-packet-sender');
const TcpTracker = require('./lib/tcp-sessions-tracker');
const DNSTracker = require('./lib/dns-tracker');
const Config = require('./config/config');
const Q = require('q');
const async = require('async-q');

/**
 * Checks privilege of current run, since often raw capture is limited to root
 */
function privsCheck() {
    if (process.getuid() !== 0) {
        console.log('Warning: not running with root privs, which are usually required for raw packet capture.');
        process.exit(0);
    }
}

/**
 * Start capture session
 * @param {WhispererConfig} config - configuration for the program as fetched from the server
 * @returns {PcapSession}
 */
function startCaptureSession(config) {
    let pcapSession;

    switch(config.capture.mode){
        case Config.FILE:
            pcapSession = pcap.createOfflineSession(config.capture.file, config.capture.filter);
            console.log(`Parsing file ${config.capture.file}`);
            break;
        case Config.INTERFACE:
            pcapSession = pcap.createSession(config.capture.interface, config.capture.filter, (config.capture.captureBufferkB * 1024 * 1024));
            console.log(`Listening on ${pcapSession.device_name}`);
            break;
    }

    return pcapSession;
}

/**
 * Start monitoring watcher
 * Checks the status of packets drop
 * TODO : Bring the knowledge back to Spider
 */
function startDropWatcher(pcapSession) {
    // Check for pcap dropped packets on an interval
    let first_drop = setInterval(function () {
        let stats = pcapSession.stats();

        if (stats && stats.ps_drop > 0) {
            debug('Pcap dropped packets, need larger buffer or less work to do: ' + JSON.stringify(stats));
            clearInterval(first_drop);
            setInterval(function () {
                debug('Pcap dropped packets: ' + JSON.stringify(stats));
            }, 5000);
        }
    }, 1000);
}

/**
 * Setup the packet listener on pcap events to send packets
 * to Spider or to file
 * @param {PcapSession} pcapSession
 * @param {WhispererConfig} config
 */
function startListeners(pcapSession, config) {
    //Initialize buffer for sending packets over the network
    let bufferWeb = new BufferedOutput(new WebSender(pcapSession.link_type, config), {sizeKB : config.packets.sendBufferSizekB, delay: config.packets.sendBufferDelay});

    //If we want to log also to file
    let bufferFile;
    if(config.dumpPackets.dumpToFile) {
        bufferFile = new BufferedOutput(new FileSender(pcapSession.link_type), {sizeKB : config.dumpPackets.fileBufferSizekB});
    }

    let dnsTracker;
    if (config.dnsCache.trackIp) {
        dnsTracker = new DNSTracker(config);
    }

    let tcpTracker;
    if(config.tcpSessions.track) {
        tcpTracker = new TcpTracker(config, dnsTracker);
    }

    function processPacket(raw_packet, packet){
        let packetId = bufferWeb.add(raw_packet, packet);

        if (config.dnsCache.trackIp){
            dnsTracker.trackIpFromPacket(packet);
        }
        
        if (config.dumpPackets.dumpToFile) {
            bufferFile.add(raw_packet);
        }
        
        if(config.tcpSessions.track) {
            tcpTracker.trackPacket(packet, packetId);
        }
    }

    // Specific processing for FILE input mode
    if(config.capture.mode === Config.FILE) {
        let allPackets = [];
        let previousTS;

        pcapSession.on('packet', function (raw_packet) {
            //We make a copy of buffers, because we process all at then end
            //If we don't copy, the new raw_packet overwrites the old one (they share the same allocated memory of [Max size of packets]
            //defined in the pcap file header
            let raw_p = {
                buf: new Buffer(raw_packet.buf),
                header: new Buffer(raw_packet.header),
                link_type: raw_packet.link_type
            };
            let packet = pcap.decode.packet(raw_p);

            //We add a pause so that we try to respect arrival rate of packets
            let packetTimestamp = packet.pcap_header.tv_sec + packet.pcap_header.tv_usec/1e6;
            let delta = previousTS ? packetTimestamp - previousTS : 0;
            previousTS = packetTimestamp;

            allPackets.push({
                delta: delta,
                packet: packet,
                raw_packet: raw_p
            });
        });

        pcapSession.on('complete', function () {
            Q.async(function *(){
                //When finish reading file, process all Packets in the order with pauses
                yield async.eachSeries(allPackets,
                    onePacket => Q.async(function * (){
                        yield Q.delay(onePacket.delta * 1e3);
                        processPacket(onePacket.raw_packet, onePacket.packet);
                })());

                //When finished processing packets, flush the buffers.
                yield bufferWeb.send();
                
                if(config.tcpSessions.track) {
                    yield tcpTracker.send();
                }

                if(config.dumpPackets.dumpToFile) {
                    yield bufferFile.send();
                }

                //Close the session
                pcapSession.close();
                process.exit(0);

            })().fail(err => {
                debug(`Error while ending process: ${err.message}`);
                console.error(err.stack);
            });
        });
    }
    //When input from network card, process packets directly, and indefinitely
    else{
        pcapSession.on('packet', function (raw_packet) {
            // No need to copy buffers as all work with raw_packet is synchronous.
            // We copy raw_packet's buffers when adding it to the file or web buffers
            let packet = pcap.decode.packet(raw_packet);
            processPacket(raw_packet, packet);
        });
    }
}

Q.async(function *(){
    // If privileges are ok
    privsCheck();

    // Start the capture
    //TODO: get parameters from outside
    const config = yield Config.WhispererConfig.initConfig(
        'http://localhost:3004',
        'sQRpSyb1SPm3uD71WYzlaQ==',
        `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCUOOUJiVL8GMnQUSeZ6hrzstEmxzg7XSsFAbDvMz7FaqeNFKoZ
no7Zohiejyl2+Hu9o3ElEIIJi1HqHjMLANMGrO6KKlJnd1aW0ySgaqGEfMi5Oixf
Q6p0IgFz0nUs2uqbjHGUKhjL+VRkNJ9xg3AJyzoVP9yGOpZRIMEftLgHbwIDAQAB
AoGAT4ydd9nIvN386h20GEnpfyNYVuySxGGDZiN7N1WUedV86R3PEQLk/e6eMfL5
uQ0xNB0U62SJtd+c7f6ZPG2L03dDBH6UoEWEN36UK7uDxTl07VbutA3O2/jqm6Cr
2tXQKr1O4/l8vrYnY278s6Q9qSzLizXEAEfLh52JHEuEpYkCQQDC3Q2OECKYd20/
4oM3a9U4XgVsVcJYUgYyvuxiwRsFOafwrlhx2Vg1QqHWPj0vjt+fi4CRz9QI8z2P
jPW4qH1zAkEAwrm75BSR0NuAV2lBKhnTPgZ9IWK/6OLQRCZdhL3RpHfOOT0kliTM
LvytT04qw63xuVlaCyb2kVzcDhgi70QPFQJALGstOtPsvuqCScy9cnWvLeEoxVAr
M+zGouyof75bBW7mHFPxr0oG9GUS9P5M/jlIOlsXXKWORNgFkWJlZMlrhwJBAJLu
66RTESR0PQe4WH+YNRncc5c5mG32mAiUmoSLZyGfdXEjffP9mETsTSpGZWZ6Xqfp
kFRR9kQBudq4w8Ofq3ECQAnGOSzZ/0dTGxfd8vs9C95vrcpAQeo9sq9o5M0dLyU7
1/AFtX5B88aEXwsWkgHzVZ3MYCWmTea6uYguhBP8qoo=
-----END RSA PRIVATE KEY-----`);

    try {
        var pcapSession = startCaptureSession(config);
    }
    catch(e){
        console.error(`Error: ${e.message}. Could not start capture, check your options.`);
        debug(e.stack);
        process.exit(0);
    }

    startDropWatcher(pcapSession);
    startListeners(pcapSession, config);
})().fail(err => {
    console.error(err.stack);
});