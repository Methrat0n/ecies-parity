"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
exports.__esModule = true;
var chai = __importStar(require("chai"));
require("mocha");
var chai_as_promised_1 = __importDefault(require("chai-as-promised"));
chai.use(chai_as_promised_1["default"]);
chai.should();
var expect = chai.expect;
var ecies = require('../../src/typescript/index');
describe('ecies', function () {
    describe('kdf', function () {
        it('should find fragment for known secret keys', function () {
            var secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex');
            var found = ecies.kdf(secret, 32);
            var expected = Buffer.from('447b68d2586f66932558575fcf9eb0ea0c3f30fe6a6915d75756fee95826a6be', 'hex');
            return found.should.eqls(expected);
        });
        it('should round the ouput length to the next 32 mutiple', function () {
            var secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex');
            var found1 = ecies.kdf(secret, 35);
            var found2 = ecies.kdf(secret, 64);
            return found1.should.eqls(found2);
        });
        it('should return an empty buffer for optoutLength = 0', function () {
            var secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex');
            var found = ecies.kdf(secret, 0);
            var expected = Buffer.from('');
            return found.should.eqls(expected);
        });
    });
    describe('getPublic', function () {
        it('should return a 65 bytes Buffer', function () { return __awaiter(void 0, void 0, void 0, function () {
            var secret, found;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex');
                        return [4 /*yield*/, ecies.getPublic(secret)];
                    case 1:
                        found = _a.sent();
                        return [2 /*return*/, found.should.have.lengthOf(65)];
                }
            });
        }); });
        it('should accept a buffer of length 32 as parameter', function () {
            var secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex');
            var found = ecies.getPublic(secret);
            return expect(found).to.be.fulfilled;
        });
        it('should NOT accept a smaller buffer as parameter', function () {
            var smallerSecret = Buffer.from('b9fc3b425d6c1745b9c9631d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex');
            var found = ecies.getPublic(smallerSecret);
            return expect(found).to.be.rejectedWith('Private key should be 32 bytes long');
        });
        it('should NOT accept a larger buffer as parameter', function () {
            var largerSecret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a098779eecc', 'hex');
            var found = ecies.getPublic(largerSecret);
            return expect(found).to.be.rejectedWith('Private key should be 32 bytes long');
        });
        it('should be possible to derive a newly generated key', function () { return __awaiter(void 0, void 0, void 0, function () {
            var secret, foundPublic, derived;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex');
                        return [4 /*yield*/, ecies.getPublic(secret)];
                    case 1:
                        foundPublic = _a.sent();
                        derived = ecies.derive(secret, foundPublic);
                        return [2 /*return*/, expect(derived).to.be.fulfilled];
                }
            });
        }); });
    });
    describe('sign', function () {
        it('should accept a 32 bytes buffer as first parameter', function () {
            var secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex');
            var msg = Buffer.alloc(10);
            var found = ecies.sign(secret, msg);
            return expect(found).to.be.fulfilled;
        });
        it('should NOT accept smaller buffer', function () {
            var smallerSecret = Buffer.from('b9fc3b425d6c1745b9c9631d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex');
            var msg = Buffer.alloc(10);
            var found = ecies.sign(smallerSecret, msg);
            return expect(found).to.be.rejectedWith('Private key should be 32 bytes long');
        });
        it('should NOT accept a larger buffer', function () {
            var largerSecret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a098779eecc', 'hex');
            var msg = Buffer.alloc(10);
            var found = ecies.sign(largerSecret, msg);
            return expect(found).to.be.rejectedWith('Private key should be 32 bytes long');
        });
        it('should NOT accept an empty message', function () {
            var secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex');
            var msg = Buffer.alloc(0);
            var found = ecies.sign(secret, msg);
            return expect(found).to.be.rejectedWith('Message should not be empty');
        });
        it('should NOT accept a message larger than 32 bytes', function () {
            var secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex');
            var msg = Buffer.alloc(33);
            var found = ecies.sign(secret, msg);
            return expect(found).to.be.rejectedWith('Message is too long (max 32 bytes)');
        });
        it('should accept a message between 1 and 32 bytes in length, included', function () {
            var secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex');
            var msg = Buffer.from('ROOOT');
            var found = ecies.sign(secret, msg);
            return expect(found).to.be.fulfilled;
        });
    });
    describe('verify', function () {
        it('should accept a public key of 65 bytes', function () {
            var pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
            var msg = Buffer.from('ROOOT');
            var sign = Buffer.from('30440220150285ea5a92decb327cba6d1065191ba7c28ed1430c0d75aec7cf37e9b2fd6a02200efdb6974ae5e728405f7893d5fc6ed5ce3823fb429119a66e2cdb438dd50233', 'hex');
            var found = ecies.verify(pub, msg, sign);
            return expect(found).to.be.fulfilled;
        });
        it('should NOT accept a public key smaller than 65 bytes', function () {
            var smallerPub = Buffer.from('04e315a987bd79b9f49d3a1c8bdda81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
            var msg = Buffer.from('ROOOT');
            var sign = Buffer.from('30440220150285ea5a92decb327cba6d1065191ba7c28ed1430c0d75aec7cf37e9b2fd6a02200efdb6974ae5e728405f7893d5fc6ed5ce3823fb429119a66e2cdb438dd50233', 'hex');
            var found = ecies.verify(smallerPub, msg, sign);
            return expect(found).to.be.rejectedWith('Public key should 65 bytes long');
        });
        it('should NOT accept a public key larger than 65 bytes', function () {
            var largerPub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a396842564', 'hex');
            var msg = Buffer.from('ROOOT');
            var sign = Buffer.from('30440220150285ea5a92decb327cba6d1065191ba7c28ed1430c0d75aec7cf37e9b2fd6a02200efdb6974ae5e728405f7893d5fc6ed5ce3823fb429119a66e2cdb438dd50233', 'hex');
            var found = ecies.verify(largerPub, msg, sign);
            return expect(found).to.be.rejectedWith('Public key should 65 bytes long');
        });
        it('should NOT accept an empty message', function () {
            var pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
            var msg = Buffer.from('');
            var sign = Buffer.from('30440220150285ea5a92decb327cba6d1065191ba7c28ed1430c0d75aec7cf37e9b2fd6a02200efdb6974ae5e728405f7893d5fc6ed5ce3823fb429119a66e2cdb438dd50233', 'hex');
            var found = ecies.verify(pub, msg, sign);
            return expect(found).to.be.rejectedWith('Message should not be empty');
        });
        it('should NOT accept a message larger than 32 bytes', function () {
            var pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
            var msg = pub; //65 bytes
            var sign = Buffer.from('30440220150285ea5a92decb327cba6d1065191ba7c28ed1430c0d75aec7cf37e9b2fd6a02200efdb6974ae5e728405f7893d5fc6ed5ce3823fb429119a66e2cdb438dd50233', 'hex');
            var found = ecies.verify(pub, msg, sign);
            return expect(found).to.be.rejectedWith('Message is too long (max 32 bytes)');
        });
        it('should be in error in case of unmatching msg and sign', function () {
            var pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
            var msg = Buffer.from('NOT ROOOT');
            var sign = Buffer.from('30440220150285ea5a92decb327cba6d1065191ba7c28ed1430c0d75aec7cf37e9b2fd6a02200efdb6974ae5e728405f7893d5fc6ed5ce3823fb429119a66e2cdb438dd50233', 'hex');
            var found = ecies.verify(pub, msg, sign);
            return expect(found).to.be.rejectedWith('Bad signature');
        });
        it('should be resolved with null in case of matching msg and sign', function () { return __awaiter(void 0, void 0, void 0, function () {
            var pub, msg, sign, found;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
                        msg = Buffer.from('ROOOT');
                        sign = Buffer.from('30440220150285ea5a92decb327cba6d1065191ba7c28ed1430c0d75aec7cf37e9b2fd6a02200efdb6974ae5e728405f7893d5fc6ed5ce3823fb429119a66e2cdb438dd50233', 'hex');
                        return [4 /*yield*/, ecies.verify(pub, msg, sign)];
                    case 1:
                        found = _a.sent();
                        return [2 /*return*/, expect(found).to.be["null"]];
                }
            });
        }); });
    });
    describe('derive', function () {
        it('should accept a private key 32 bytes long and a public key 65 bytes long', function () {
            var secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex');
            var pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
            var found = ecies.derive(secret, pub);
            return expect(found).to.be.fulfilled;
        });
        it('should NOT accept a secret key smaller than 32 bytes', function () {
            var smallerSecret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a37c0bf85dc1130b8a0', 'hex');
            var pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
            var found = ecies.derive(smallerSecret, pub);
            return expect(found).to.be.rejectedWith("Bad private key, it should be 32 bytes but it's actualy " + smallerSecret.length + " bytes long");
        });
        it('should NOT accept a secret key larger than 32 bytes', function () {
            var largerSecret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a05773623846', 'hex');
            var pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
            var found = ecies.derive(largerSecret, pub);
            return expect(found).to.be.rejectedWith("Bad private key, it should be 32 bytes but it's actualy " + largerSecret.length + " bytes long");
        });
        it('should NOT accept a public key larger than 65 bytes', function () {
            var secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex');
            var largerPub = Buffer.from('04e315a987bd79b9f49d6372748723a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
            var found = ecies.derive(secret, largerPub);
            return expect(found).to.be.rejectedWith("Bad public key, it should be 65 bytes but it's actualy " + largerPub.length + " bytes long");
        });
        it('should NOT accept a public key smaller than 65 bytes', function () {
            var secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex');
            var smallerPub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a24222505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
            var found = ecies.derive(secret, smallerPub);
            return expect(found).to.be.rejectedWith("Bad public key, it should be 65 bytes but it's actualy " + smallerPub.length + " bytes long");
        });
        it('should NOT accept a public key begginning with something else than 4', function () {
            var secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex');
            var smallerPub = Buffer.from('03e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
            var found = ecies.derive(secret, smallerPub);
            return expect(found).to.be.rejectedWith("Bad public key, a valid public key would begin with 4");
        });
        it('should derive a new shared secret', function () { return __awaiter(void 0, void 0, void 0, function () {
            var secret, pub, found, expected;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex');
                        pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
                        return [4 /*yield*/, ecies.derive(secret, pub)];
                    case 1:
                        found = _a.sent();
                        expected = Buffer.from('38b23cedbacdd74cc6faf140d4103daa57cf717703b043ad1b93da0c18d9f7ed', 'hex');
                        return [2 /*return*/, found.should.eqls(expected)];
                }
            });
        }); });
    });
    describe('encrypt', function () {
        it('should accept public key 65 bytes long and a message between 1 and 32 bytes included', function () {
            var pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
            var msg = Buffer.from('ROOOT');
            var found = ecies.encrypt(pub, msg);
            return expect(found).to.be.fulfilled;
        });
        it('should NOT accept a public key larger than 65 bytes', function () {
            var largerPub = Buffer.from('04e315a987bd79b9f49d6372748723a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
            var msg = Buffer.from('ROOOT');
            var found = ecies.encrypt(largerPub, msg);
            return expect(found).to.be.rejectedWith("Bad public key, it should be 65 bytes but it's actualy " + largerPub.length + " bytes long");
        });
        it('should NOT accept a public key smaller than 65 bytes', function () {
            var smallerPub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a24222505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
            var msg = Buffer.from('ROOOT');
            var found = ecies.encrypt(smallerPub, msg);
            return expect(found).to.be.rejectedWith("Bad public key, it should be 65 bytes but it's actualy " + smallerPub.length + " bytes long");
        });
        it('should NOT accept a public key begginning with something else than 4', function () {
            var smallerPub = Buffer.from('03e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
            var msg = Buffer.from('ROOOT');
            var found = ecies.encrypt(smallerPub, msg);
            return expect(found).to.be.rejectedWith("Bad public key, a valid public key would begin with 4");
        });
        it('should accept a opts.ephemPrivateKey of 32 bytes', function () {
            var secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex');
            var pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
            var msg = Buffer.from('ROOOT');
            var found = ecies.encrypt(pub, msg, { ephemPrivateKey: secret });
            return expect(found).to.be.fulfilled;
        });
        it('should NOT accept a opts.ephemPrivateKey smaller than 32 bytes', function () {
            var smallerSecret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a37c0bf85dc1130b8a0', 'hex');
            var pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
            var msg = Buffer.from('ROOOT');
            var found = ecies.encrypt(pub, msg, { ephemPrivateKey: smallerSecret });
            return expect(found).to.be.rejectedWith("Bad private key, it should be 32 bytes but it's actualy " + smallerSecret.length + " bytes long");
        });
        it('should NOT accept a opts.ephemPrivateKey larger than 32 bytes', function () {
            var largerSecret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a05773623846', 'hex');
            var pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
            var msg = Buffer.from('ROOOT');
            var found = ecies.encrypt(pub, msg, { ephemPrivateKey: largerSecret });
            return expect(found).to.be.rejectedWith("Bad private key, it should be 32 bytes but it's actualy " + largerSecret.length + " bytes long");
        });
        it('should NOT be deterministic', function () { return __awaiter(void 0, void 0, void 0, function () {
            var pub, msg, found1, found2;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
                        msg = Buffer.from('ROOOT');
                        return [4 /*yield*/, ecies.encrypt(pub, msg)];
                    case 1:
                        found1 = _a.sent();
                        return [4 /*yield*/, ecies.encrypt(pub, msg)];
                    case 2:
                        found2 = _a.sent();
                        return [2 /*return*/, found1.should.not.eqls(found2)];
                }
            });
        }); });
    });
    describe('decrypt', function () {
        var metaLength = 1 + 64 + 16 + 32;
        it('should accept a 32 bytes private key with an encrypted message', function () {
            var secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex');
            var encrypted = Buffer.from('041891f11182f69dfd67dc190ccd649445182c6474f69c9f3885c99733b056fb53e1a30b90b6d2a2624449fda885adcba50334024b20081b07f95f3cc92a93dbedccf75890cd7ac088b0810058c272ef25a4028875342c5dfc36b54f156cd26b69109625e5374bc689c79196d98ccc9ad5b7099e6484', 'hex');
            var found = ecies.decrypt(secret, encrypted);
            return found.should.be.fulfilled;
        });
        it('should NOT accept a secret key smaller than 32 bytes', function () {
            var smallerSecret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a37c0bf85dc1130b8a0', 'hex');
            var encrypted = Buffer.from('041891f11182f69dfd67dc190ccd649445182c6474f69c9f3885c99733b056fb53e1a30b90b6d2a2624449fda885adcba50334024b20081b07f95f3cc92a93dbedccf75890cd7ac088b0810058c272ef25a4028875342c5dfc36b54f156cd26b69109625e5374bc689c79196d98ccc9ad5b7099e6484', 'hex');
            var found = ecies.decrypt(smallerSecret, encrypted);
            return expect(found).to.be.rejectedWith("Bad private key, it should be 32 bytes but it's actualy " + smallerSecret.length + " bytes long");
        });
        it('should NOT accept a secret key larger than 32 bytes', function () {
            var largerSecret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a05773623846', 'hex');
            var encrypted = Buffer.from('041891f11182f69dfd67dc190ccd649445182c6474f69c9f3885c99733b056fb53e1a30b90b6d2a2624449fda885adcba50334024b20081b07f95f3cc92a93dbedccf75890cd7ac088b0810058c272ef25a4028875342c5dfc36b54f156cd26b69109625e5374bc689c79196d98ccc9ad5b7099e6484', 'hex');
            var found = ecies.decrypt(largerSecret, encrypted);
            return expect(found).to.be.rejectedWith("Bad private key, it should be 32 bytes but it's actualy " + largerSecret.length + " bytes long");
        });
        it('should NOT accept an encrypted msg begginning with a false public key', function () {
            var largerSecret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a05773623846', 'hex');
            var encryptedWithFalsePublicKey = Buffer.from('031891f11182f69dfd67dc190ccd649445182c6474f69c9f3885c99733b056fb53e1a30b90b6d2a2624449fda885adcba50334024b20081b07f95f3cc92a93dbedccf75890cd7ac088b0810058c272ef25a4028875342c5dfc36b54f156cd26b69109625e5374bc689c79196d98ccc9ad5b7099e6484', 'hex');
            var found = ecies.decrypt(largerSecret, encryptedWithFalsePublicKey);
            return expect(found).to.be.rejectedWith("Not valid ciphertext. A valid ciphertext would begin with 4");
        });
        it("should NOT accept an encrypted msg smaller than " + metaLength + " bytes", function () {
            var largerSecret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a05773623846', 'hex');
            var smallerEncrypted = Buffer.from('041891f11182f69dfd67dc190c1a30b90b6d2a2624449fda885adcba50334024b20081b07f95f3cc92a93dbedccf75890cd7ac088b0810058c272ef25a4028875342c5dfc36b54f156cd26b69109625e5374bc689c79196d98ccc9ad5b7099e6484', 'hex');
            var found = ecies.decrypt(largerSecret, smallerEncrypted);
            return expect(found).to.be.rejectedWith("Invalid Ciphertext. Data is too small. It should ba at least 113");
        });
    });
    describe('encrypt and decrypte', function () {
        it('should be invariant', function () { return __awaiter(void 0, void 0, void 0, function () {
            var pub, expected, msg, encrypted, secret, decrypted;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
                        expected = 'ROOOT';
                        msg = Buffer.from(expected);
                        return [4 /*yield*/, ecies.encrypt(pub, msg)];
                    case 1:
                        encrypted = _a.sent();
                        secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex');
                        return [4 /*yield*/, ecies.decrypt(secret, encrypted)];
                    case 2:
                        decrypted = _a.sent();
                        return [2 /*return*/, decrypted.toString().should.eqls(expected)];
                }
            });
        }); });
        it('should fail to decrypt if encrypted with another keypair', function () { return __awaiter(void 0, void 0, void 0, function () {
            var msg, owner1Pub, encrypted, owner2Secret, decrypted;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        msg = Buffer.from('Edgewhere');
                        owner1Pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
                        return [4 /*yield*/, ecies.encrypt(owner1Pub, msg)];
                    case 1:
                        encrypted = _a.sent();
                        owner2Secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c');
                        decrypted = ecies.decrypt(owner2Secret, encrypted);
                        return [2 /*return*/, expect(decrypted).to.be.rejectedWith('Incorrect MAC')];
                }
            });
        }); });
    });
    describe('sign and verify', function () {
        it('shoud be invariant', function () { return __awaiter(void 0, void 0, void 0, function () {
            var expected, msg, secret, signed, pub, found;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        expected = 'ROOOT';
                        msg = Buffer.from(expected);
                        secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex');
                        return [4 /*yield*/, ecies.sign(secret, msg)];
                    case 1:
                        signed = _a.sent();
                        pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex');
                        return [4 /*yield*/, ecies.verify(pub, msg, signed)];
                    case 2:
                        found = _a.sent();
                        return [2 /*return*/, expect(found).to.be["null"]];
                }
            });
        }); });
    });
});
