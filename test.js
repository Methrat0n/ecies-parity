var expect = require("chai").expect;
var createHash = require("crypto").createHash;
var bufferEqual = require("buffer-equal");
var ecies = require("./");
var crypto = require("crypto");

// TODO: Add more ECIES tests

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

var msg = createHash("sha256").update("test").digest();
var otherMsg = createHash("sha256").update("test2").digest();
var shortMsg = createHash("sha1").update("test").digest();

var privateKey = Buffer(32);
privateKey.fill(1);
var publicKey = ecies.getPublic(privateKey);

var privateKeyA = Buffer(32);
privateKeyA.fill(2);
var publicKeyA = ecies.getPublic(privateKeyA);

ecies.from

var privateKeyB = Buffer(32);
privateKeyB.fill(3);

// parity-specifc vars
var publicKeyB = ecies.getPublic(privateKeyB);
var testPrivateKey=Buffer.from('677d558860e2a5b735952b1133e6c613018fc0ad3e81d04bbf8975dd63a28258','hex');
var testReceiverPrivateKey=Buffer.from('dbd770b0ec84c57a5c2920558e1e28aac808a126822ff74401f26fdaef49c861', 'hex');
var testPubKey=ecies.getPublic(testPrivateKey);
var testReceiverPubKey= ecies.getPublic(testReceiverPrivateKey);
var testIV = Buffer.from('d0198031fcd63151667eadf3537f6a6b','hex');

ecies.encrypt(
  Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex'),
  Buffer.from("Edgewhere")
).then(crypted => {
  console.log('lalalalalalalal')
  console.log(crypted.toString('base64'))
})

ecies.decrypt(
  Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex'),
  Buffer.from('BC4wAFMjg2/L88dxY35/5xHWDdfz66vHEveZdns7dcdxhPs02xZjXFiracGAOOeZBU3N+5llXlfaBr3IZ6RJHsyO5wSklsas5yDiR20AKp0GcQl4Pg1jSKn5jg5hYZZmn+nYVYl8dhzWaX2CaDowVvSRp1wmLHhE34w=', 'base64')
).then(decrypted => {
  console.log('lolololololoo')
  console.log(decrypted.toString())
  console.log(decrypted.toString() === 'Edgewhere')
}).catch(err => 
  console.error(err)  
)