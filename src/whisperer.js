#!/usr/bin/env node
/**
 * Created by TincaTibo on 30/01/16.
 * @author TincaTibo@gmail.com
 * @version 0.1
 */

var pcap = require('pcap');
var debug = require('debug')('whisperer');
var BufferedOutput = require('./lib/buffered-output');
var WebSender = require('./lib/web-packet-sender');
var FileSender = require('./lib/file-packet-sender');
var TcpTracker = require('./lib/tcp-sessions-tracker');
var Config = require('./config/config');

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
    if (! config.f) {
        // default filter is all IPv4 TCP, which is all we know how to decode right now anyway
        config.f = 'ip proto \\tcp';
    }
    var pcapSession;
    //pcapSession = pcap.createSession(config.capture.interface, config.capture.filter, (config.capture.captureBufferkB * 1024 * 1024));
    pcapSession = pcap.createOfflineSession('../test/test-1session2reqHTTP.pcap', config.capture.filter);
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
    var first_drop = setInterval(function () {
        var stats = pcapSession.stats();

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
    var bufferWeb = new BufferedOutput(new WebSender(pcapSession.link_type, config), {sizeKB : config.packets.sendBufferSizekB, delaySec: config.packets.sendBufferDelaySec});

    //If we want to log also to file
    var bufferFile;
    if(config.dumpPackets.dumpToFile) {
        bufferFile = new BufferedOutput(new FileSender(pcapSession.link_type), {sizeKB : config.dumpPackets.fileBufferSizekB});
    }

    var tcpTracker = new TcpTracker(config);
    var packetId, packet;

    pcapSession.on('packet', function (raw_packet) {
        packet = pcap.decode.packet(raw_packet);
        packetId = bufferWeb.add(raw_packet, packet);

        if(config.dumpPackets.dumpToFile) {
            bufferFile.add(raw_packet);
        }

        tcpTracker.trackPacket(packet, packetId);

    });

    pcapSession.on('complete', function () {
        bufferWeb.send();

        if(config.dumpPackets.dumpToFile) {
            bufferFile.send();
        }

        setTimeout(function () {
            tcpTracker.send();
        }, 1000);

        //Waiting for end of asyn calls
        //TODO: Improve with real ending
        setTimeout(function () {
            pcapSession.close();
            process.exit(0);
        }, 3000);
    });
}

// If privileges are ok
privsCheck();

// Start the capture
var config = new Config().getConfig();
var pcapSession = startCaptureSession(config);
startDropWatcher(pcapSession);
startListeners(pcapSession, config);
