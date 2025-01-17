/**
 * Browser ecies-geth implementation.
 * This is based of the eccrypto js module.
 */

import { ec as EC } from 'elliptic'

//IE 11
declare global {
  interface Window {
    msCrypto?: Crypto
 }
  interface Crypto {
    webkitSubtle?: SubtleCrypto
  }
}

const ec = new EC('secp256k1')
const crypto = window.crypto || window.msCrypto!
const subtle: SubtleCrypto = (crypto.subtle || crypto.webkitSubtle)!

if(subtle === undefined || crypto === undefined) //TODO maybe better ?
  console.error('crypto and/or subtle api unavailable')
  //throw new Error('crypto and/or subtle api unavailable')

// Use the browser RNG
const randomBytes = (size: number): Buffer =>
  crypto.getRandomValues(Buffer.alloc(size))

// Get the browser SHA256 implementation
const sha256 = (msg: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer): PromiseLike<Buffer> =>
  subtle.digest({name: "SHA-256"}, msg).then(Buffer.from)

// The KDF as implemented in Parity
export const kdf = (secret: Buffer, outputLength: number): Promise<Buffer> => { 
  let ctr = 1
  let written = 0
  let willBeResult = Promise.resolve(Buffer.from(''))
  while (written < outputLength) {
    const ctrs = Buffer.from([ctr >> 24, ctr >> 16, ctr >> 8, ctr])
    const willBeHashResult = sha256(Buffer.concat([ctrs,secret]))
    willBeResult = willBeResult.then(result => willBeHashResult.then(hashResult =>
      Buffer.concat([result, hashResult])
    ))
    written += 32
    ctr +=1
  }
  return willBeResult;
}

// AES-128-CTR is used in the Parity implementation
// Get the AES-128-CTR browser implementation
const getAes = (op: typeof subtle.encrypt | typeof subtle.decrypt) => (
  counter: Buffer,
  key: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer,
  data: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer
) =>
  subtle
    .importKey("raw", key, "AES-CTR", false, [op.name])
    .then(cryptoKey =>
      op({ name: "AES-CTR", counter: counter, length: 128 }, cryptoKey, data)
    ).then(Buffer.from)

const aesCtrEncrypt = getAes(subtle.encrypt)
const aesCtrDecrypt = getAes(subtle.decrypt)

const hmacSha256Sign = (
  key: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer,
  msg: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer
): PromiseLike<Buffer> => {
  const algorithm = { name: "HMAC", hash: { name: "SHA-256" } }
  return subtle.importKey("raw", key, algorithm, false, ["sign"])
  .then(cryptoKey => subtle.sign(algorithm, cryptoKey, msg))
  .then(Buffer.from)
}

const hmacSha256Verify = (
  key: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer,
  msg: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer,
  sig: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer,
): PromiseLike<boolean> => {
  const algorithm = { name: "HMAC", hash: { name: "SHA-256" } }
  const keyp = subtle.importKey("raw", key, algorithm, false, ["verify"])
  return keyp.then(cryptoKey => subtle.verify(algorithm, cryptoKey, sig, msg))
}

/**
 * Compute the public key for a given private key.
 * @param {Buffer} privateKey - A 32-byte private key
 * @return {Promise<Buffer>} A promise that resolve with the 65-byte public key or reject on wrong private key.
 * @function
 */
export const getPublic = (privateKey: Buffer): Promise<Buffer> => new Promise((resolve, reject) => {
  if(privateKey.length !== 32)
    reject(new Error('Bad private key'))
  else
    resolve(Buffer.from(ec.keyFromPrivate(privateKey).getPublic('array')))
})

/**
 * Create an ECDSA signature.
 * @param {Buffer} privateKey - A 32-byte private key
 * @param {Buffer} msg - The message being signed, no more than 32 bytes
 * @return {Promise.<Buffer>} A promise that resolves with the
 * signature and rejects on bad key or message.
 */
export const sign = (privateKey: Buffer, msg: Buffer): Promise<Buffer> =>
  new Promise((resolve, reject) => {
    if(privateKey.length !== 32)
      reject(new Error('Bad private key'))
    else if(msg.length <= 0)
      reject(new Error('Message should not be empty'))
    else if(msg.length > 32)
      reject(new Error('Message is too long'))
    else
      resolve(Buffer.from(ec.sign(msg, privateKey, { canonical: true }).toDER('hex'), 'hex'))
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
    if(publicKey.length !== 65 || publicKey[0] !== 4)
      reject(new Error('Bad public key'))
    else if(msg.length <= 0)
      reject(new Error('Message should not be empty'))
    else if(msg.length > 32)
      reject(new Error('Message is too long'))
    else if (!ec.verify(msg, sig.toString('hex') as any, publicKey, 'hex'))
      reject(new Error("Bad signature"))
    else
      resolve(null)
  })

/**
 * Derive shared secret for given private and public keys.
 * @param {Buffer} privateKey - Sender's private key (32 bytes)
 * @param {Buffer} publicKey - Recipient's public key (65 bytes)
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
export const encrypt = (publicKeyTo: Buffer, msg: Buffer, opts?: {iv?: Buffer, ephemPrivateKey?: Buffer}): Promise<Buffer> => {
  opts = opts || {}
  const ephemPrivateKey = opts.ephemPrivateKey || randomBytes(32)
  const willBeSharedPx = derive(ephemPrivateKey, publicKeyTo)
  const willBeHash = willBeSharedPx.then(sharedPx => kdf(sharedPx, 32))
  const iv = opts.iv || randomBytes(16)
  const willBeEncryptionKey = willBeHash.then(hash => hash.slice(0, 16))
  const willBeMacKey = willBeHash.then(hash =>  sha256(hash.slice(16)))
  const willBeCipherText = willBeEncryptionKey.then(encryptionKey => aesCtrEncrypt(iv, encryptionKey, msg))
  const willBeIvCipherText = willBeCipherText.then(cipherText => Buffer.concat([iv, cipherText]))
  const willBeHMAC = willBeMacKey.then(macKey => willBeIvCipherText.then(ivCipherText => hmacSha256Sign(macKey, ivCipherText)))
  const willBeEphemPublicKey = getPublic(ephemPrivateKey)
  return willBeEphemPublicKey.then(ephemPublicKey => willBeIvCipherText.then(ivCipherText => willBeHMAC.then(HMAC =>
    Buffer.concat([ephemPublicKey, ivCipherText, HMAC])
  )))
}

const metaLength = 1 + 64 + 16 + 32; 
/**
 * Decrypt message using given private key.
 * @param {Buffer} privateKey - A 32-byte private key of recepient of
 * the mesage
 * @param {Ecies} encrypted - ECIES serialized structure (result of ECIES encryption)
 * @return {Promise.<Buffer>} - A promise that resolves with the
 * plaintext on successful decryption and rejects on failure.
 */
export const decrypt = (privateKey: Buffer, encrypted: Buffer): Promise<Buffer> => 
  new Promise((resolve, reject) => {
    if(encrypted.length <= metaLength)
      reject(new Error(`Invalid Ciphertext. Data is too small, should be more than ${metaLength} bytes`))
    else if(encrypted[0] < 2 && encrypted[0] > 4)
      reject(new Error(`Not a valid ciphertext. It should begin with 2, 3 or 4 but actualy begin with ${encrypted[0]}`))
    else {
      // deserialise
      const ephemPublicKey = encrypted.slice(0,65)
      const cipherTextLength = encrypted.length - metaLength;
      const iv = encrypted.slice(65,65 + 16)
      const cipherAndIv = encrypted.slice(65, 65+16+ cipherTextLength)
      const ciphertext = cipherAndIv.slice(16)
      const msgMac = encrypted.slice(65+16+ cipherTextLength)

      // check HMAC
      const willBePx = derive(privateKey, ephemPublicKey)
      const willBeHash = willBePx.then(px => kdf(px, 32))
      const willBeEncryptionKey = willBeHash.then(hash => hash.slice(0, 16))
      const willBeMacKey = willBeHash.then(hash => sha256(hash.slice(16)))
      willBeMacKey.then(macKey => hmacSha256Verify(macKey, cipherAndIv, msgMac))
      .then(isHmacGood => willBeEncryptionKey.then(encryptionKey => {
        if(!isHmacGood)
          reject(new Error('Incorrect MAC'))
        else {
          // decrypt message
          aesCtrDecrypt(iv, encryptionKey, ciphertext).then(plainText =>
            resolve(Buffer.from(plainText))
          )
        }
      })).catch(reject)
    }
  }
)
