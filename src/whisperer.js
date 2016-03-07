#!/usr/bin/env node
/**
 * Created by TincaTibo on 30/01/16.
 * @author TincaTibo@gmail.com
 * @version 0.1
 */
"use strict";

var pcap = require('pcap');
var debug = require('debug')('whisperer');
var BufferedOutput = require('./lib/buffered-output');
var WebSender = require('./lib/web-packet-sender');
var FileSender = require('./lib/file-packet-sender');
var TcpTracker = require('./lib/tcp-sessions-tracker');
var Config = require('./config/config');
var async = require('async');
var _ = require('lodash');

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
            break;
        case Config.INTERFACE:
            pcapSession = pcap.createSession(config.capture.interface, config.capture.filter, (config.capture.captureBufferkB * 1024 * 1024));
            break;
    }

    console.log('Listening on ' + pcapSession.device_name);
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
            debug('pcap dropped packets, need larger buffer or less work to do: ' + JSON.stringify(stats));
            clearInterval(first_drop);
            setInterval(function () {
                debug('pcap dropped packets: ' + JSON.stringify(stats));
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
    let bufferWeb = new BufferedOutput(new WebSender(pcapSession.link_type, config), {sizeKB : config.packets.sendBufferSizekB, delaySec: config.packets.sendBufferDelaySec});

    //If we want to log also to file
    let bufferFile;
    if(config.dumpPackets.dumpToFile) {
        bufferFile = new BufferedOutput(new FileSender(pcapSession.link_type), {sizeKB : config.dumpPackets.fileBufferSizekB});
    }

    let tcpTracker = new TcpTracker(config);

    function processPacket(raw_packet, packet, callback){
        let packetId = bufferWeb.add(raw_packet, packet);

        if (config.dumpPackets.dumpToFile) {
            bufferFile.add(raw_packet);
        }

        tcpTracker.trackPacket(packet, packetId);

        if(callback){
            callback(null);
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
            }
            let packet = pcap.decode.packet(raw_p);

            //We add a pause so that we try to respect arrival rate of packets
            let packetTimestamp = packet.pcap_header.tv_sec + packet.pcap_header.tv_usec/1e6
            let delta = previousTS ? packetTimestamp - previousTS : 0;
            previousTS = packetTimestamp;

            allPackets.push({
                raw_packet: raw_p,
                packet: packet,
                delta: delta
                });
        });

        pcapSession.on('complete', function () {

            //When finish reading file, process all Packets in the order with pauses
            async.eachSeries(
                allPackets,
                (item, callback) => {
                    setTimeout(processPacket, item.delta * 1e3, item.raw_packet, item.packet, callback);
                },
                () => {
                    //When finished processing packets, flush the buffers.

                    //TODO: add errors callback
                    //TODO: Improve with real ending (async all steps, or better, use a generator)
                    bufferWeb.send();

                    if(config.dumpPackets.dumpToFile) {
                        bufferFile.send();
                    }

                    setTimeout(function () {
                        tcpTracker.send();
                    }, 1000);

                    //Close the session
                    setTimeout(function () {
                        pcapSession.close();
                        process.exit(0);
                    }, 3000);
                }
            );
        });
    }
    //When input from network card, process packets directly
    else{
        pcapSession.on('packet', function (raw_packet) {
            // No need to copy buffers as all work with raw_packet is synchronous.
            // We copy raw_packet's buffers when adding it to the file or web buffers
            let packet = pcap.decode.packet(raw_packet);
            processPacket(raw_packet, packet);
        });
    }
}

// If privileges are ok
privsCheck();

// Start the capture
var config = new Config.WhispererConfig().getConfig();

try {
    var pcapSession = startCaptureSession(config);
}
catch(e){
    console.error(`Error: ${e.message}. Could not start capture, check your options.`);
    process.exit(0);
}

startDropWatcher(pcapSession);
startListeners(pcapSession, config);
