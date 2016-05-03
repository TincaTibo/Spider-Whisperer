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
        '+X7mSwxyRzqreBwXeDD9Cw==',
        `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCvAqf7f9daEQvjfTFO+JrF3+BlzDH4SpB1IzNrbFTjrKKUcyQs
WcYECkzWX8eAE/46wQw2xzXJjjgIFLHjFlcyz4sBLcoecFC0lk013DtqIuVOCjmB
9v5weCDDYbaO9j9RQ1+kfgCBXac9a0VmZDgvq1s7KjB1fbNQgzo/slw2iwIDAQAB
AoGAaprymneQRbPWixdqntE+7kPmW/wbgERjZIcxvkD6IMm7KzRMF5wDy9g+X+Nu
Ee2b0kxf1UpZ0FIKfZmllk+4gx//6eB5M+75I9qgWTqhlwt4YMnb4S2E5+RbvJhB
7TPt+Bf8+dq/c7yEdP7xjCWS5Hc6GhHolYIlqNXaPgmBDWkCQQDZ94rIplDXYNDl
J9GkgC2952ZxWkri/qOtbHsRexU7I6TtJcxfD9caA+FMYKWjAA6lETnBH2qzgjYC
/oZWdYY9AkEAzYxErNooT1G3OmHYN25gM9K9R0klTlqbaaAR7x2W7BmJobps8qBp
9Uy9ncPAtyuceVkPf7zQxrIiA2W/OMdEZwJAF6uPMb0F+G22IbySQqf8z6uqb1Lb
4QzAH5wxPTO9mX+EcJBzQjuJI3UaaV3xfuMJtBlLyVItFzNjxC15zzfSDQJAP8f2
x2wqdfJ1WLhjz0+AqpQKB8S6vsV+1BfHeNtFqZ2DB5xBkkgUmPlnHT1Q34W42C66
kHiWkBFWXJeF7qhmoQJAQLRKeEhBrdjHkrfAayo4IXx/1OcndFMByW160up4rgtU
1AKVwAUtoQsWYn2CcBPd7tzQL38Mc59tYhKPPtMpgw==
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