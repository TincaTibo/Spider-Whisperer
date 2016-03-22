/**
 * Original code: node-pcap @mranney
 */

'use strict';

const dns = require('dns');
const Q = require('q');
const debug = require('debug')('dns-cache');
const moment = require('moment');

// Cache reverse DNS lookups for the life of the program. TTL: 1 day (by default)

class DNSCache {
    constructor(config) {
        this.cache = new Map;
        this.ttl = moment.duration(config.dnsCache.ttl);
        
        //regular purge every day
        setInterval(that => that.purge(),
            moment.duration(config.dnsCache.purgeDelay), this);
    }

    reverse(ip) {
        let that = this;
        return Q.async(function * (){
            const now = moment();
            //If we have already stored this IP in cache
            if (that.cache.get(ip)
                && that.cache.get(ip).lastUpdate > moment().subtract(that.ttl)) {

                that.cache.get(ip).lastSeen = now;
                return that.cache.get(ip).hostname || ip;
            }
            else {
                that.cache.set(ip,{
                    hostname: null,
                    ip: ip,
                    lastUpdate: now,
                    lastSeen: now
                });

                try {
                    const domains = yield Q.nfcall(dns.reverse(ip));
                    that.cache.get(ip).hostname = domains[0];
                }
                catch (e){
                    debug(`Could not get hostname for ${ip}.`);
                }

                return that.cache.get(ip).hostname || ip;
            }
        })();
    }

    getItemsUpdatedSince(moment){
        let res = [];
        for(let item of this.cache){
            if(item.lastUpdate > moment) {
                res.push(item);
            }
        }
        return res;
    }
    
    purge(){
        for(let key of this.cache.keys()){
            if(this.cache.get(key).lastSeen > moment().subtract(this.ttl)) {
                debug(`Removed IP ${key}, not seen since TTL: ${this.ttl.humanize()}`);
                this.cache.delete(key);
            }
        }
    }
}

module.exports = DNSCache;
