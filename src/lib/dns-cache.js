/**
 * Original code: node-pcap @mranney
 */

const dns = require('dns');
const Q = require('q');
const debug = require('debug')('dns-cache');
const moment = require('moment');

// Cache reverse DNS lookups for the life of the program. TTL: 1 day (by default)

class DNSCache {
    constructor(config) {
        this.cache = new Map;
        this.ttl = moment.duration(config.dnsCache.ttl);
    }

    reverse(ip) {
        let that = this;
        return Q.async(function * (){
            //If we have already stored this IP in cache
            if (that.cache.get(ip)
                && that.cache.get(ip).lastUpdate > moment().subtract(that.ttl)) {

                return that.cache.get(ip).hostname || ip;
            }
            else {
                that.cache.set(ip,{
                    hostname: null,
                    lastUpdate: moment()
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
}

module.exports = DNSCache;
