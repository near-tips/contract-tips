import BigInteger from 'big-integer';

const zero = BigInteger(0);
const one = BigInteger(1);
const n256 = BigInteger(256);

function fromLittleEndian(bytes) {
    let result = zero;
    let base = one;
    bytes.forEach(function (byte) {
        result = result.add(base.multiply(BigInteger(byte)));
        base = base.multiply(n256);
    });
    return result;
}

function fromBigEndian(bytes) {
  return fromLittleEndian(bytes.reverse());
}

function toLittleEndian(bigNumber) {
    let result = new Uint8Array(8);
    let i = 0;
    while (bigNumber.greater(zero)) {
        result[i] = bigNumber.mod(n256);
        bigNumber = bigNumber.divide(n256);
        i += 1;
    }
    return result;
}

function toBigEndian(bytes) {
  return toLittleEndian(bytes).reverse();
}

console.log('Reading BigInteger from an array of bytes');
let bigInt = new BigInteger(1643203633);
console.log(bigInt.toString());

console.log('Writing BigInteger to an array of bytes');
let bytes = toBigEndian(bigInt);
console.log(bytes);