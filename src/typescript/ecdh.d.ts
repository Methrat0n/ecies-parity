declare module 'ecdh' {
  function derive(privkey_a: Buffer, pubkey_b: Buffer, shared: Buffer): Buffer
}