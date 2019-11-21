import * as chai from 'chai'
import 'mocha'
import chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)

type ECIES = typeof import('../../src/typescript/node') //only import type from the node
const ecies = require('../../src/typescript/index') as ECIES

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