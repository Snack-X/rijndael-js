"use strict";

const Rijndael = require("./rijndael");
const Utils = require("./utils");

// Available sizes, modes
const SIZES = [16, 24, 32];
const MODES = ["ecb", "cbc"];

//==============================================================================

class RijndaelBlock {
  constructor(key, mode) {
    let keySize = key.length;

    if(!SIZES.includes(keySize))
      throw `Unsupported key size: ${keySize * 8} bit`;

    if(!MODES.includes(mode))
      throw `Unsupported mode: ${mode}`;

    this.key = Utils.toArray(key);
    this.keySize = keySize;
    this.mode = mode;
  }

  encrypt(_plaintext, blockSize, _iv) {
    blockSize = parseInt(blockSize);

    if(blockSize <= 32 && !SIZES.includes(blockSize))
      throw `Unsupported block size: ${blockSize * 8} bit`;
    else if(32 < blockSize) {
      blockSize /= 8;
      if(!SIZES.includes(blockSize))
        throw `Unsupported block size: ${blockSize} bit`;
    }

    if(this.mode === "cbc") {
      if(!_iv)
        throw `IV is required for mode ${this.mode}`;
      if(_iv.length !== blockSize)
        throw `IV size should match with block size (${blockSize * 8} bit)`;
    }

    let plaintext = Utils.toArray(_plaintext);
    let padLength = plaintext.length % blockSize;
    if(padLength !== 0) padLength = blockSize - padLength;
    while(padLength --> 0) plaintext.push(0);

    let blockCount = plaintext.length / blockSize;
    let ciphertext = new Array(plaintext.length);

    let cipher = new Rijndael(this.key);

    switch(this.mode) {
      case "ecb":
        for(let i = 0 ; i < blockCount ; i++) {
          let start = i * blockSize, end = (i + 1) * blockSize;
          let block = plaintext.slice(start, end);

          let encrypted = cipher.encrypt(block);
          for(let j = 0 ; j < blockSize ; j++)
            ciphertext[start + j] = encrypted[j];
        }

        break;

      case "cbc":
        let iv = Utils.toArray(_iv);

        for(let i = 0 ; i < blockCount ; i++) {
          let start = i * blockSize, end = (i + 1) * blockSize;
          let block = plaintext.slice(start, end);

          for(let j = 0 ; j < blockSize ; j++) block[j] ^= iv[j];

          let encrypted = cipher.encrypt(block);
          for(let j = 0 ; j < blockSize ; j++)
            ciphertext[start + j] = encrypted[j];

          iv = encrypted.slice();
        }

        break;
    }

    return Buffer.from(ciphertext);
  }

  decrypt(_ciphertext, blockSize, _iv) {
    blockSize = parseInt(blockSize);

    if(blockSize <= 32 && !SIZES.includes(blockSize))
      throw `Unsupported block size: ${blockSize * 8} bit`;
    else if(32 < blockSize) {
      blockSize /= 8;
      if(!SIZES.includes(blockSize))
        throw `Unsupported block size: ${blockSize} bit`;
    }

    if(this.mode === "cbc") {
      if(!_iv)
        throw `IV is required for mode ${this.mode}`;
      if(_iv.length !== blockSize)
        throw `IV size should match with block size (${blockSize * 8} bit)`;
    }

    let ciphertext = Utils.toArray(_ciphertext);
    if(ciphertext.length % blockSize !== 0)
      throw `Ciphertext length should be multiple of ${blockSize * 8} bit`;

    let blockCount = ciphertext.length / blockSize;
    let plaintext = new Array(ciphertext.length);

    let cipher = new Rijndael(this.key);

    switch(this.mode) {
      case "ecb":
        for(let i = 0 ; i < blockCount ; i++) {
          let start = i * blockSize, end = (i + 1) * blockSize;
          let block = ciphertext.slice(start, end);

          let decrypted = cipher.decrypt(block);
          for(let j = 0 ; j < blockSize ; j++)
            plaintext[start + j] = decrypted[j];
        }

        break;

      case "cbc":
        let iv = Utils.toArray(_iv);

        for(let i = 0 ; i < blockCount ; i++) {
          let start = i * blockSize, end = (i + 1) * blockSize;
          let block = ciphertext.slice(start, end);

          let decrypted = cipher.decrypt(block);
          for(let j = 0 ; j < blockSize ; j++)
            plaintext[start + j] = decrypted[j] ^ iv[j];

          iv = block.slice();
        }

        break;
    }

    return Buffer.from(plaintext);
  }
}

module.exports = RijndaelBlock;
