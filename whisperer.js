#!/usr/bin/env node
/**
 * Created by tibo on 30/01/16.
 */

var pcap = require('pcap');
var Sender = require('./sender');
var debug = require('debug')('whisperer');
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
    pcap_session = pcap.createOfflineSession('./test/test-1reqHTTP.pcap', config.filter);
    console.log('Listening on ' + pcap_session.device_name);
}

function get_config() {
    config.interface = 'eth0';
    config.filter = 'tcp port 80';
    config.captureBuffer = '10';
    //Buffer of bytes used to buffer send
    config.sendBufferSizekB = '100';
    config.sendBufferDelaySec = '10';
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
    const sendBuffer = new Buffer(config.sendBufferSizekB*1024);
    const sendBufferLen = sendBuffer.length;
    var bytesInSendBuffer = 0;

    var sender = new Sender(pcap_session.link_type);
    function send(){
        sender.send(new Buffer(sendBuffer).slice(0,bytesInSendBuffer));
        bytesInSendBuffer = 0;
    }

    //Set timeout for sending buffer if not enough packets (but still some)
    var interval_send = setInterval(function () {
        if(bytesInSendBuffer){
            send();
        }
    },config.sendBufferDelaySec * 1000);

    pcap_session.on('packet', function (raw_packet) {
        //Get packet size
        var psize=raw_packet.header.readUInt32LE(8, true);
        //If adding it to buffer would get an overflow, send buffer and clear buffer
        if(bytesInSendBuffer + psize + raw_packet.header.length > sendBufferLen){
            send();
        }
        //Add to buffer
        raw_packet.header.copy(sendBuffer,bytesInSendBuffer);
        bytesInSendBuffer+=raw_packet.header.length;
        raw_packet.buf.copy(sendBuffer,bytesInSendBuffer,0,psize-1);
        bytesInSendBuffer+=psize;
    });

    pcap_session.on('complete', function () {
        //If there are bytes to send, we send before leaving
        if(bytesInSendBuffer){
            send();
            //Waiting for end of asyn calls
            //TODO: Improve with real ending
            setTimeout(function () {
                pcap_session.close();
                process.exit(0);
            }, 1000);
        }
    });
}


// Start the program
get_config();
privs_check();
start_capture_session();
start_drop_watcher();
setup_listeners();
