# Rijndael-JS

This is an implementation of Rijndael algorithm.

Supports 128/192/256 bit key/block, and ECB, CBC modes.

Unlike [`node-rijndael`](https://github.com/skeggse/node-rijndael), or [`node-mcrypt`](https://github.com/tugrul/node-mcrypt), this is an **pure-JS** implementation.

Unlike [`js-rijndael`](https://github.com/kraynel/js-rijndael), this is licensed under MIT License.

## Usage

```js
const Rijndael = require('rijndael-js');

// If you are using this module in Node.js environment (or `Buffer` exists in global context),
// every data (key, iv, plaintext, ciphertext) will be converted to byte array using `Buffer.from`
// For what can be converted, please refer to Node.js documentation:
//     https://nodejs.org/api/buffer.html#buffer_class_buffer

// If you are using this module in web browser environment,
// data should be one of:
// - <TypedArray>, which will be converted into <Uint8Array>
// - <String>, which will be converted into UTF-8 byte array
// - array-like object, which:
//     - can be accepted by `Array.from()` method
//       https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/from
//     - every element is an integer <Number> within uint8_t range (0x00 ~ 0xff)

// Key can be 16/24/32 bytes long (128/192/256 bit)
const key = 'Lorem ipsum dolor sit amet, cons';

// Plaintext will be zero-padded
const original = 'Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do';

// IV is necessary for CBC mode
// IV should have same length with the block size
const iv = 'Ut enim ad minim veniam, quis no';

// Create Rijndael instance
// `new Rijndael(key, mode)`
const cipher = new Rijndael(key, 'cbc');

// `Rijndael.encrypt(plaintext, blockSize[, iv]) -> <Array>`
// Output will always be <Array> where every element is an integer <Number>
const ciphertext = Buffer.from(cipher.encrypt(original, 256, iv));

ciphertext.toString("base64");
// -> bmwLDaLiI1k0oUu5wx9dlWs+Uuw3IhIkMYvq0VsVlQY66wAAqS0djh8N+SZJNHsv8wBRfhytRX2p9LJ0GT3sig==

// `Rijndael.decrypt(ciphertext, blockSize[, iv]) -> <Array>`
const plaintext = Buffer.from(cipher.decrypt(ciphertext, 256, iv));

original === plaintext.toString();
// -> true
```

## Changelog

### v2.0.0

- **Type of return data has changed to `Array`, from `Buffer`**
- Internal code convention change
- Improve compatibility with non-node environment

### v1.0.0

Initial release
