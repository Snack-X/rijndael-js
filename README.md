# Rijndael-JS

This is an implementation of Rijndael algorithm.

Supports 128/192/256 bit key/block, and ECB, CBC modes.

Unlike [`node-rijndael`](https://github.com/skeggse/node-rijndael), or [`node-mcrypt`](https://github.com/tugrul/node-mcrypt), this is an **pure-JS** implementation.

Unlike [`js-rijndael`](https://github.com/kraynel/js-rijndael), this is licensed under MIT License.

## Usage

```
const Rijndael = require("rijndael-js");

// Every input (key, iv, plaintext, ciphertext) will be converted to byte array
// using `Buffer.from`
// Therefore it could be one of:
//   <Array>
//   <TypedArray>
//   <ArrayBuffer>
//   <Buffer>
//   (UTF-8 Encoded) <String>

// Key can be 16/24/32 bytes long (128/192/256 bit)
let key = "Lorem ipsum dolor sit amet, cons";

// Plaintext will be zero-padded
let original = "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do";

// IV is necessary for CBC mode
// IV should have same length with the block size
let iv = "Ut enim ad minim veniam, quis no";

// Create Rijndael instance
let cipher = new Rijndael(key, "cbc");

// `.encrypt(plaintext, blockSize, iv) -> Buffer`
// Output will be always <Buffer>
let ciphertext = cipher.encrypt(original, 256, iv);

ciphertext.toString("hex");
  // bmwLDaLiI1k0oUu5wx9dlWs+Uuw3IhIkMYvq0VsVlQY66wAAqS0djh8N+SZJNHsv8wBRfhytRX2p9LJ0GT3sig==

// `.decrypt(ciphertext, blockSize, iv) -> Buffer`
let plaintext = cipher.decrypt(ciphertext, 256, iv);

original === plaintext.toString();
  // true
```
