'use strict';

const Q = require('q');
const debug = require('debug')('dns-tracker');
const DNSCache = require('./dns-cache');
const moment = require('moment');
const request = require('../utils/requestAsPromise');
const zlib = require('zlib');
const Config = require('../config/config').WhispererConfig;

const IPv4 = require('pcap/decode/ipv4');

const FULL = Symbol();
const UPDATE = Symbol();

class DNSTracker {
    constructor(config) {
        this.dnsCache = new DNSCache(config);
        this.lastSentDate = moment();
        
        //on regular intervals, get DNSCache changes
        //send the changes to Spider
        //hostnames are used on GUI for hostname display, but can be overriden by configuration on Whisps
        setInterval(that => {
            that.send(UPDATE).fail(err => {
                debug(`Error while sending Hostnames to Spider: ${err.message}`);
                console.error(err);
            });
        }, moment.duration(config.dnsCache.sendUpdateDelay).asMilliseconds(), this);

        setInterval(that => {
            that.send(FULL).fail(err => {
                debug(`Error while sending Hostnames to Spider: ${err.message}`);
                console.error(err);
            });
        }, moment.duration(config.dnsCache.sendFullDelay).asMilliseconds(), this);

        //Options to export to Spider-Config
        this.options = {
            method: 'POST',
            uri: `${config.dnsCache.spiderURI}/${config.whisperer}/hosts/v1`,
            headers: {
                'Content-Type': 'application/json',
                'Content-Encoding': 'gzip'
            },
            gzip: true,
            time: true, //monitors the request
            timeout: moment.duration(config.dnsCache.spiderTimeout).asMilliseconds()
        };
    }

    trackIpFromPacket(packet) {
        const that = this;
        Q.async(function * (){
            if (packet.payload.payload instanceof IPv4){
                const ip  = packet.payload.payload;

                const srcIp = ip.saddr.addr.join('.');
                const dstIp = ip.daddr.addr.join('.');

                //add IPs to DNS Cache
                yield Q.all([that.dnsCache.reverse(srcIp),that.dnsCache.reverse(dstIp)]);
            }
        })().fail(err => console.error(err));
    }
    
    send(type){
        let that = this;
        return Q.async(function * (){
            let items = null;

            if(type === UPDATE){
                items = that.dnsCache.getItemsUpdatedSince(that.lastSentDate);
            }
            else{
                items = that.dnsCache.getItems();
            }
            that.lastSentDate = moment();

            debug(`${items.length} items to send.`);
            
            if(items.length){
                //send to Whisperer
                const zbf = yield Q.nfcall(zlib.gzip, JSON.stringify(items));

                that.options.body = zbf;
                that.options.headers['Content-Length'] = zbf.length;
                that.options.headers['Authorization'] = `Bearer ${Config.getInstance().token}`;

                const res = yield request(that.options);

                debug(`ResponseStatus: ${res.response.statusCode} in ${res.response.elapsedTime}ms`);
                if (res.response.statusCode != 202) {
                    debug(res.body);
                }
            }

        })();
    }

    setIpAsServer(ip){
        this.dnsCache.setIpAsServer(ip);
    }

    setIpAsClient(ip){
        this.dnsCache.setIpAsClient(ip);
    }
}

module.exports = DNSTracker;