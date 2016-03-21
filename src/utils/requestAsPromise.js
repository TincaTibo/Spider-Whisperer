const Q = require('q');
const request = require('request');

module.exports = function (options){
    return Q.Promise(function (resolve, reject){
        request(options, (err, res, body) => {
            if (err) {
                reject(err);
            }
            else {
                resolve({
                    response: res,
                    body: body
                });
            }
        });
    });
};