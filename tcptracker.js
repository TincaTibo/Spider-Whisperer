function TcpTracker(){
    this.sessions = {};
}

TcpTracker.prototype.trackPacket = function (packet, packetId) {

}

module.exports = TcpTracker;