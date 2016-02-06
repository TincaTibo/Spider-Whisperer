const fs = require('fs');
const http = require('http');
const zlib = require('zlib');
var debug = require('debug')('sender');


//TODO: change to closure
var Sender = function (link_type){
    this.link_type = link_type;
    this.globalHeader = null;
    this.dataLinksTypes = null;

    //For libpcap file format, see: https://wiki.wireshark.org/Development/LibpcapFileFormat
    this.dataLinksTypes = {
        "LINKTYPE_NULL": 0, /* BSD loopback encapsulation */
        "LINKTYPE_ETHERNET": 1, /* Ethernet (10Mb) */
        "LINKTYPE_IEEE802_11_RADIO": 127,
        "LINKTYPE_RAW": 12,
        "LINKTYPE_LINUX_SLL": 113
    };

    this.globalHeader = new Buffer(24); //Size of Libpcapfileformat globalheader
    this.globalHeader.writeUInt32LE(0xa1b2c3d4,0); //Magicnumber for nanosecond resolution files (libpcap>1.5.0)
    this.globalHeader.writeUInt16LE(2,4); //Major version of libpcap file format. Current: 2.4
    this.globalHeader.writeUInt16LE(4,6); //Minor version
    this.globalHeader.writeInt32LE(0,8); //Timestamps are in GMT, so 0
    this.globalHeader.writeUInt32LE(0,12); //Time precision
    this.globalHeader.writeUInt32LE(65535,16); //Max size of packets
    this.globalHeader.writeUInt32LE(this.dataLinksTypes[this.link_type],20); //Datalink

    this.i = 0;

    //Options to export to Spider-Pack
    this.options = {
        hostname: 'localhost',
        port: 3000,
        path: '/packets/v1',
        method: 'POST',
        headers: {
            'Content-Type': 'application/vnd.tcpdump.pcap',
            'Content-Encoding': 'gzip'
        }
    };

};

Sender.prototype.send = function (bf) {
    //TODO: improve this by removing concat and sending both buffer to the zip. Perf tests needed.
    var bfToSend = Buffer.concat([this.globalHeader,bf],this.globalHeader.length + bf.length);

    var req = http.request(this.options, (res) => {
        debug(`STATUS: ${res.StatusCode}`);
    });
    req.on('error', (err) => {
        console.log(`problem with request: ${er.message}`);
    });
    req.setTimeout(2000, ()=> {
        debug('Request timed out');
    });
    zlib.gzip(bfToSend, (err, zbf) => {
        if (err) {
            console.log(err);
        }
        else {
            this.options.headers['Content-Length'] = zbf.length;
            req.write(zbf);
            req.end();
        }
    });
};

Sender.prototype.sendToFile = function (bf) {
    //Export to file
    fs.open(fileName, 'w', function (err,fd) {
        if (err) throw err;

        //Global header writing
        fs.write(fd, globalHeader, 0, globalHeader.length, function (err, written, buffer) {
            if (err) throw err;

            //Packets writing
            fs.write(fd, bf, 0, bf.length, written, function (err, written, buffer) {
                if (err) throw err;

                //Close file at the end of buffer
                fs.close(fd, function (err) {
                    if (err) throw err;
                    console.log(fileName + ': Saved!');
                });
            });
        });
    });
};

module.exports = Sender;