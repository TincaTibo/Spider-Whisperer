'use strict';

const Q = require('q');
const debug = require('debug')('dns-tracker');
const DNSCache = require('./dns-cache');
const moment = require('moment');
const request = require('../utils/requestAsPromise');
const zlib = require('zlib');

const IPv4 = require('pcap/decode/ipv4');

class DNSTracker {
    constructor(config) {
        this.dnsCache = new DNSCache(config);
        this.lastSentDate = moment();
        
        //on regular intervals, get DNSCache changes
        //send the changes to Whisperer Config server
        //hostnames are used on GUI for hostname display, but can be overriden by configuration on Whisperer Config
        setInterval(that => {
            that.send().fail(err => {
                debug(`Error while sending Hostnames to Spider: ${err.message}`);
                console.error(err);
            });
        }, moment.duration(config.dnsCache.sendDelay), this);

        //Options to export to Spider-Config
        this.options = {
            method: 'POST',
            uri: config.dnsCache.spiderConfigURI,
            headers: {
                'Content-Type': 'application/json',
                'Content-Encoding': 'gzip'
            },
            gzip: true,
            time: true, //monitors the request
            timeout: moment.duration(config.dnsCache.spiderConfigTimeout).asMilliseconds()
        };
    }

    trackIpFromPacket(packet) {
        if (packet.payload.payload instanceof IPv4){
            const ip  = packet.payload.payload;

            const srcIp = ip.saddr.addr.join('.');
            const dstIp = ip.daddr.addr.join('.');

            const that = this;
            //add IPs to DNS Cache
            Q.async(function * (){
                yield Q.all([that.dnsCache.reverse(srcIp),that.dnsCache.reverse(dstIp)]);
            })();
        }
    }
    
    send(){
        let that = this;
        return Q.async(function * (){
            let items = that.dnsCache.getItemsUpdatedSince(that.lastSentDate);
            debug(`${items.length} items to send.`);
            
            if(items.length){
                //send to Whisperer
                const zbf = yield Q.nfcall(zlib.gzip, JSON.stringify(items));

                that.options.body = zbf;
                that.options.headers['Content-Length'] = zbf.length;

                const res = yield request(that.options);

                debug(`ResponseStatus: ${res.response.statusCode} in ${res.response.elapsedTime}ms`);
                if (res.response.statusCode != 202) {
                    debug(res.body);
                }
            }
        })();
    }
}

module.exports = DNSTracker;