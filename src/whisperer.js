#!/usr/bin/env node
/**
 * Created by tibo on 30/01/16.
 */

var pcap = require('pcap');
var debug = require('debug')('whisperer');
var BufferedOutput = require('./lib/bufferedoutput');
var packetSenders = require('./lib/packetSenders');
var TcpTracker = require('./lib/tcptracker');

var pcap_session, config = {};

function privs_check() {
    if (process.getuid() !== 0) {
        console.log('Warning: not running with root privs, which are usually required for raw packet capture.');
        process.exit(0);
    }
}

function start_capture_session() {
    if (! config.f) {
        // default filter is all IPv4 TCP, which is all we know how to decode right now anyway
        config.f = 'ip proto \\tcp';
    }
    //pcap_session = pcap.createSession(config.interface, config.filter, (config.captureBuffer * 1024 * 1024));
    pcap_session = pcap.createOfflineSession('../test/test-nreqHTTP.pcap', config.filter);
    console.log('Listening on ' + pcap_session.device_name);
}

function get_config() {
    return {
        interface : 'wlan0',
        filter : 'tcp port 80',
        captureBuffer : 10,
        sendBufferSizekB : 100,
        sendBufferDelaySec : 5,
        sendSessionDelaySec : 5,
        sessionTimeOutSec : 120,
        dumpToFile : false,
        fileBufferSizekB : 1000,
        spiderPackURI : 'http://localhost:3000/packets/v1',
        spiderPackTimeout: 2000
    }
}

function start_drop_watcher() {
    // Check for pcap dropped packets on an interval
    var first_drop = setInterval(function () {
        var stats = pcap_session.stats();
        if (stats && stats.ps_drop > 0) {
            console.log('pcap dropped packets, need larger buffer or less work to do: ' + JSON.stringify(stats));
            clearInterval(first_drop);
            setInterval(function () {
                console.log('pcap dropped packets: ' + JSON.stringify(stats));
            }, 5000);
        }
    }, 1000);
}

function setup_listeners() {
    //Initialize buffer for sending packets over the network
    var bufferWeb = new BufferedOutput(new packetSenders.WebSender(config, pcap_session.link_type), {sizeKB : config.sendBufferSizekB, delaySec: config.sendBufferDelaySec});

    //If we want to log also to file
    var bufferFile;
    if(config.dumpToFile) {
        bufferFile = new BufferedOutput(new packetSenders.FileSender(pcap_session.link_type), {sizeKB : config.fileBufferSizekB});
    }

    var tcpTracker = new TcpTracker({
        delaySec: config.sendSessionDelaySec,
        sessionTimeOutSec : config.sessionTimeOutSec
    });
    var packetId, packet;

    pcap_session.on('packet', function (raw_packet) {
        packet = pcap.decode.packet(raw_packet);
        packetId = bufferWeb.add(raw_packet, packet);

        if(config.dumpToFile) {
            bufferFile.add(raw_packet);
        }

        tcpTracker.trackPacket(packet, packetId);

    });

    pcap_session.on('complete', function () {
        bufferWeb.send();

        if(config.dumpToFile) {
            bufferFile.send();
        }

        tcpTracker.send();

        //Waiting for end of asyn calls
        //TODO: Improve with real ending
        setTimeout(function () {
             pcap_session.close();
             process.exit(0);
        }, 2000);
    });
}

// Start the program
get_config();
privs_check();
start_capture_session();
start_drop_watcher();
setup_listeners();
