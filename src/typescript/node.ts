/**
 * Note: This module is based off the original eccrypto module
 */

import { createHash, BinaryLike, createCipheriv, createDecipheriv, createHmac } from 'crypto'
import * as secp256k1 from 'secp256k1' //TODO tiny-secp instead ?
import  * as ecdh from './build/Release/ecdh'

const sha256 = (msg: BinaryLike): Buffer =>
  createHash("sha256").update(msg).digest()

const hmacSha256 = (key: BinaryLike, msg: BinaryLike): Buffer =>
  createHmac("sha256", key).update(msg).digest()

const aes128CtrEncrypt = (iv: Buffer, key: Buffer, plaintext: Buffer): Buffer => {
  const cipher = createCipheriv("aes-128-ctr", key, iv)
  const firstChunk = cipher.update(plaintext)
  const secondChunk = cipher.final()
  return Buffer.concat([iv, firstChunk, secondChunk])
}

const aes128CtrDecrypt = (iv: Buffer, key: Buffer, ciphertext: Buffer): Buffer => {
  var cipher = createDecipheriv("aes-128-ctr", key, iv);
  var firstChunk = cipher.update(ciphertext);
  var secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

// Compare two buffers in constant time to prevent timing attacks.
const equalConstTime = (b1: Buffer, b2: Buffer): boolean => {
  if (b1.length !== b2.length) {
    return false
  }
  let res = 0;
  for (let i = 0; i < b1.length; i++) {
    res |= b1[i] ^ b2[i]
  }
  return res === 0;
}

const pad32 = (msg: Buffer): Buffer => {
  if(msg.length < 32) {
    const buff = new Buffer(32).fill(0)
    msg.copy(buff, 32 - msg.length)
    return buff
  } else return msg
}

// The KDF as implemented in Parity
export const kdf = async function(secret: Buffer, outputLength: number): Promise<Buffer> { 
  let ctr = 1;
  let written = 0; 
  let result = Buffer.from('');
  while (written < outputLength) {
    const ctrs = Buffer.from([ctr >> 24, ctr >> 16, ctr >> 8, ctr])
    const hashResult = await sha256(Buffer.concat([ctrs,secret]))
    result = Buffer.concat([result, hashResult])
    written += 32
    ctr +=1
  }
  return result;
}

/**
 * Compute the public key for a given private key.
 * @param {Buffer} privateKey - A 32-byte private key
 * @return {Buffer | Error } A 65-byte public key or an error if the private key wasn't valid.
 * @function
 */
export const getPublic = (privateKey: Buffer): Buffer | Error => 
  privateKey.length !== 32
  ? new Error("Bad private key")
  : secp256k1.publicKeyConvert(secp256k1.publicKeyCreate(privateKey), false) // See https://github.com/wanderer/secp256k1-node/issues/46

/**
 * Create an ECDSA signature.
 * @param {Buffer} privateKey - A 32-byte private key
 * @param {Buffer} msg - The message being signed
 * @return {Promise.<Buffer | Error>} A promise that resolves with the
 * signature and rejects on bad key or message.
 */
export const sign = (privateKey: Buffer, msg: Buffer): Promise<Buffer> =>
  new Promise((resolve, reject) => {
    if(msg.length < 0)
      reject(new Error("Message should not be empty"))
    else if(msg.length >= 32)
      reject(new Error("Message is too long"))
    else {
      const padded = pad32(msg)
      const signed = secp256k1.sign(padded, privateKey).signature
      resolve(secp256k1.signatureExport(signed));
    }
  })

/**
 * Verify an ECDSA signature.
 * @param {Buffer} publicKey - A 65-byte public key
 * @param {Buffer} msg - The message being verified
 * @param {Buffer} sig - The signature
 * @return {Promise.<null>} A promise that resolves on correct signature
 * and rejects on bad key or signature.
 */
export const verify = (publicKey: Buffer, msg: Buffer, sig: Buffer): Promise<null> =>
  new Promise((resolve, reject) => {
    if(msg.length < 0) {
      reject(new Error('Message should not be empty'))
    } else if(msg.length >= 32) {
      reject(new Error('Message is too long'))
    } else {
      const passed = pad32(msg)
      const signed = secp256k1.signatureImport(sig)

      if (secp256k1.verify(passed, signed, publicKey)) {
        resolve(null);
      } else {
        reject(new Error("Bad signature"));
       }
    } 
  })

/**
 * Derive shared secret for given private and public keys.
 * @param {Buffer} privateKeyA - Sender's private key (32 bytes)
 * @param {Buffer} publicKeyB - Recipient's public key (65 bytes)
 * @return {Promise.<Buffer>} A promise that resolves with the derived
 * shared secret (Px, 32 bytes) and rejects on bad key.
 */
export const derive = (privateKeyA: Buffer, publicKeyB: Buffer) =>
  new Promise(resolve => {
    resolve(ecdh.derive(privateKeyA, publicKeyB));
  })

/**
 * Input/output structure for ECIES operations.
 * @typedef {Object} Ecies
 * @property {Buffer} iv - Initialization vector (16 bytes)
 * @property {Buffer} ephemPublicKey - Ephemeral public key (65 bytes)
 * @property {Buffer} ciphertext - The result of encryption (variable size)
 * @property {Buffer} mac - Message authentication code (32 bytes)
 */

/**
 * Encrypt message for given recepient's public key.
 * @param {Buffer} publicKeyTo - Recipient's public key (65 bytes)
 * @param {Buffer} msg - The message being encrypted
 * @param {?{?iv: Buffer, ?ephemPrivateKey: Buffer}} opts - You may also
 * specify initialization vector (16 bytes) and ephemeral private key
 * (32 bytes) to get deterministic results.
 * @return {Promise.<Buffer>} - A promise that resolves with the ECIES
 * structure on successful encryption and rejects on failure.
 */
exports.encrypt = async function(publicKeyTo, msg, opts) {
  opts = opts || {};
  let ephemPrivateKey = opts.ephemPrivateKey || crypto.randomBytes(32);
  let sharedPx = await derive(ephemPrivateKey, publicKeyTo);
  let hash = await kdf(sharedPx, 32);
  let encryptionKey = hash.slice(0, 16);
  let iv = opts.iv || crypto.randomBytes(16);
  let macKey = sha256(hash.slice(16));
  let ciphertext = aes128CtrEncrypt(iv, encryptionKey, msg);
  let HMAC = hmacSha256(macKey, ciphertext);
  let ephemPublicKey = getPublic(ephemPrivateKey)
  return Buffer.concat([ephemPublicKey,ciphertext,HMAC]);
};

/**
 * Decrypt message using given private key.
 * @param {Buffer} privateKey - A 32-byte private key of recepient of
 * the mesage
 * @param {Ecies} opts - ECIES structure (result of ECIES encryption)
 * @return {Promise.<Buffer>} - A promise that resolves with the
 * plaintext on successful decryption and rejects on failure.
 */
exports.decrypt = async function(privateKey, encrypted) {
  let metaLength = 1 + 64 + 16 + 32;
  assert(encrypted.length > metaLength, "Invalid Ciphertext. Data is too small")
  assert(encrypted[0] >= 2 && encrypted[0] <= 4, "Not valid ciphertext.")
  // deserialise
  let ephemPublicKey = encrypted.slice(0,65);
  let cipherTextLength = encrypted.length - metaLength; 
  let iv = encrypted.slice(65,65 + 16);
  let cipherAndIv = encrypted.slice(65, 65+16+ cipherTextLength);
  let ciphertext = cipherAndIv.slice(16);
  let msgMac = encrypted.slice(65+16+ cipherTextLength);

  // check HMAC
  let px = await derive(privateKey, ephemPublicKey);
  let hash = await kdf(px,32);
  let encryptionKey = hash.slice(0, 16);
  let macKey = await sha256(hash.slice(16));
  let currentHMAC = await hmacSha256(macKey, cipherAndIv);
  assert(equalConstTime(currentHMAC, msgMac), "Incorrect MAC");
  // decrypt message
  let plainText = await aes128CtrDecrypt(iv, encryptionKey, ciphertext);
  return Buffer.from(new Uint8Array(plainText));
};