/**
 * Note: This module is based off the original eccrypto module
 */

import { createHash, BinaryLike, createCipheriv, createDecipheriv, createHmac, randomBytes } from 'crypto'
import * as secp256k1 from 'secp256k1' //TODO this dependency can probably be remove
import { ec as EC } from 'elliptic'

const ec = new EC('secp256k1')

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
 * @return {Promise<Buffer>} A promise that resolve with the 65-byte public key or reject on wrong private key.
 * @function
 */
export const getPublic = (privateKey: Buffer): Promise<Buffer> => new Promise((resolve, reject) =>
  privateKey.length !== 32
  ? reject(new Error("Bad private key"))
  : resolve(secp256k1.publicKeyConvert(secp256k1.publicKeyCreate(privateKey), false)) // See https://github.com/wanderer/secp256k1-node/issues/46
)

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
export const derive = (privateKeyA: Buffer, publicKeyB: Buffer): Promise<Buffer> =>
  new Promise((resolve, reject) => {
    if(privateKeyA.length !== 32)
      reject(new Error(`Bad private key, it should be 32 bytes but it's actualy ${privateKeyA.length} bytes long`))
    else if(publicKeyB.length !== 65)
      reject(new Error(`Bad public key, it should be 65 bytes but it's actualy ${publicKeyB.length} bytes long`))
    else if(publicKeyB[0] !== 4)
      reject(new Error(`Bad public key, a valid public key would begin with 4`))
    else {
      const keyA = ec.keyFromPrivate(privateKeyA);
      const keyB = ec.keyFromPublic(publicKeyB);
      const Px = keyA.derive(keyB.getPublic());  // BN instance
      resolve(Buffer.from(Px.toArray()))
    }
  })

/**
 * Encrypt message for given recepient's public key.
 * @param {Buffer} publicKeyTo - Recipient's public key (65 bytes)
 * @param {Buffer} msg - The message being encrypted
 * @param {?{?iv: Buffer, ?ephemPrivateKey: Buffer}} opts - You may also
 * specify initialization vector (16 bytes) and ephemeral private key
 * (32 bytes) to get deterministic results.
 * @return {Promise.<Buffer>} - A promise that resolves with the ECIES structure serialized
 */
export const encrypt = async (publicKeyTo: Buffer, msg: Buffer, opts?: {iv?: Buffer, ephemPrivateKey?: Buffer}): Promise<Buffer> => {
  opts = opts || {};
  const ephemPrivateKey = opts.ephemPrivateKey || randomBytes(32);
  const sharedPx = await derive(ephemPrivateKey, publicKeyTo);
  const hash = await kdf(sharedPx, 32);
  const encryptionKey = hash.slice(0, 16);
  const iv = opts.iv || randomBytes(16);
  const macKey = sha256(hash.slice(16));
  const ciphertext = aes128CtrEncrypt(iv, encryptionKey, msg);
  const HMAC = hmacSha256(macKey, ciphertext);
  const ephemPublicKey = await getPublic(ephemPrivateKey)
  return Buffer.concat([ephemPublicKey,ciphertext,HMAC]);
}

/**
 * Decrypt message using given private key.
 * @param {Buffer} privateKey - A 32-byte private key of recepient of
 * the mesage
 * @param {Ecies} encrypted - ECIES serialized structure (result of ECIES encryption)
 * @return {Promise.<Buffer>} - A promise that resolves with the
 * plaintext on successful decryption and rejects on failure.
 */
export const decrypt = async (privateKey: Buffer, encrypted: Buffer): Promise<Buffer> => {
  const metaLength = 1 + 64 + 16 + 32
  if(encrypted.length < metaLength)
    return Promise.reject(new Error('Invalid Ciphertext. Data is too small'))
  else if(encrypted[0] < 2 && encrypted[0] > 4)
    return Promise.reject(new Error('Not valid ciphertext.'))
  
  // deserialise
  const ephemPublicKey = encrypted.slice(0,65)
  const cipherTextLength = encrypted.length - metaLength;
  const iv = encrypted.slice(65,65 + 16)
  const cipherAndIv = encrypted.slice(65, 65+16+ cipherTextLength)
  const ciphertext = cipherAndIv.slice(16)
  const msgMac = encrypted.slice(65+16+ cipherTextLength)

  // check HMAC
  const px = await derive(privateKey, ephemPublicKey)
  const hash = await kdf(px, 32)
  const encryptionKey = hash.slice(0, 16)
  const macKey = sha256(hash.slice(16))
  const currentHMAC = hmacSha256(macKey, cipherAndIv)

  if(!equalConstTime(currentHMAC, msgMac))
    return Promise.reject('Incorrect MAC')

  // decrypt message
  const plainText = aes128CtrDecrypt(iv, encryptionKey, ciphertext)
  return Buffer.from(new Uint8Array(plainText))
}