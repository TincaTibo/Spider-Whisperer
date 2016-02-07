var packetSenders = require('./packetSenders');

//TODO: refactor with inheritance: SendBuffer & SendBufferWithTimeout

var WebBuffer = function (linkType, sizeKB, delaySec){
    this.buf = new Buffer(sizeKB * 1024);
    this.sender = new packetSenders.WebSender(linkType);
    this.bytes = 0;

    //Set timeout for sending buffer if not enough packets (but still some)
    this.interval_send = setInterval(function () {
        if(this.bytes){
            this.send();
        }
    }, delaySec * 1000);
}

function FileBuffer(linkType, sizeKB){
    this.buf = new Buffer(sizeKB * 1024);
    this.sender = new packetSenders.FileSender(linkType);
    this.bytes = 0;

}

var send = function (){
    if(this.bytes) {
        this.sender.send(new Buffer(this.buf).slice(0, this.bytes));
        bytes = 0;
    }
}

var add = function (raw_packet){
    //Get packet size
    var psize=raw_packet.header.readUInt32LE(8, true);

    //If adding it to buffer would get an overflow, send buffer and clear buffer
    if(this.bytes + psize + raw_packet.header.length > this.buf.length){
        this.send();
    }

    //Add to buffer
    raw_packet.header.copy(this.buf, this.bytes);
    this.bytes += raw_packet.header.length;

    raw_packet.buf.copy(this.buf, this.bytes, 0, psize-1);
    this.bytes += psize;
}

WebBuffer.prototype.send = send;
FileBuffer.prototype.send = send;

WebBuffer.prototype.add = add;
FileBuffer.prototype.add = add;

exports.WebBuffer = WebBuffer;
exports.FileBuffer = FileBuffer;