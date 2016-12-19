"use strict";

const Precalculated = require("./rijndael-precalculated");
const Utils = require("./utils");

// Available sizes
const SIZES = [16, 24, 32];

// ROUNDS [blockSize] [keySize]
const ROUNDS = {
  "16": { "16": 10, "24": 12, "32": 14 },
  "24": { "16": 12, "24": 12, "32": 14 },
  "32": { "16": 14, "24": 14, "32": 14 },
};

const SBOX = Precalculated.SBOX;
const RCON = Precalculated.RCON;
const ROW_SHIFT = Precalculated.ROW_SHIFT;

const MUL_02 = Precalculated.MUL2;
const MUL_03 = Precalculated.MUL3;
const MUL_09 = Precalculated.MUL9;
const MUL_11 = Precalculated.MUL11;
const MUL_13 = Precalculated.MUL13;
const MUL_14 = Precalculated.MUL14;

//==============================================================================

class Rijndael {
  constructor(key) {
    let keySize = key.length;

    if(!SIZES.includes(keySize))
      throw "Unsupported key size: " + (keySize * 8) + "bit";

    this.key = Utils.toArray(key);
    this.keySize = keySize;
  }

  ExpandKey(blockSize) {
    let keySize = this.key.length;
    let roundCount = ROUNDS[blockSize][keySize];
    let keyCount = roundCount + 1;
    let expandedKey = new Array(keyCount * blockSize);

    // First key is original key
    for(let i = 0 ; i < keySize ; i++) expandedKey[i] = this.key[i];

    let rconIndex = 0;

    for(let i = keySize ; i < expandedKey.length ; i += 4) {
      // Take previous word
      let temp = expandedKey.slice(i - 4, i);

      // First 4 bytes
      if(i % keySize === 0) {
        // Key Schedule Core
        // 1. Rotate 8 bit left
        // 2. Apply S-box on every byte
        // 3. First byte ^= RCON[rconIndex]
        temp = [
          SBOX[temp[1]] ^ RCON[rconIndex],
          SBOX[temp[2]],
          SBOX[temp[3]],
          SBOX[temp[0]],
        ];

        // Use next RCON
        rconIndex++;
      }

      // Fill three word
      if(i % keySize < 16) {
        for(let j = 0 ; j < 4 ; j++)
          expandedKey[i + j] = expandedKey[i - keySize + j] ^ temp[j];
      }

      // End of 128 bit key processing
      if(keySize === 16) continue;

      // For 256 bit key
      if(keySize === 32 && i % keySize === 16) {
        temp = [
          SBOX[temp[0]],
          SBOX[temp[1]],
          SBOX[temp[2]],
          SBOX[temp[3]],
        ];

        for(let j = 0 ; j < 4 ; j++)
          expandedKey[i + j] = expandedKey[i - keySize + j] ^ temp[j];
      }
      // For 192 bit and 256 bit key, fill left one/three blocks
      else {
        for(let j = 0 ; j < 4 ; j++)
          expandedKey[i + j] = expandedKey[i - keySize + j] ^ temp[j];
      }
    }

    return expandedKey;
  }

  AddRoundKey(block, key, keyIndex) {
    let blockSize = block.length;

    for(let i = 0 ; i < blockSize ; i++)
      block[i] ^= key[keyIndex * blockSize + i];
  }

  SubBytes(block) {
    for(let i = 0 ; i < block.length ; i++)
      block[i] = SBOX[block[i]];
  }

  SubBytesReversed(block) {
    for(let i = 0 ; i < block.length ; i++)
      block[i] = SBOX.indexOf(block[i]);
  }

  ShiftRows(block) {
    let output = [];

    for(let i = 0 ; i < block.length ; i++)
      output[i] = block[ROW_SHIFT[block.length][i]];

    for(let i = 0 ; i < block.length ; i++)
      block[i] = output[i];
  }

  ShiftRowsReversed(block) {
    let output = [];

    for(let i = 0 ; i < block.length ; i++)
      output[i] = block[ROW_SHIFT[block.length].indexOf(i)];

    for(let i = 0 ; i < block.length ; i++)
      block[i] = output[i];
  }

  MixColumns(block) {
    for(let i = 0 ; i < block.length ; i += 4) {
      // b0 = 2a0 + 3a1 + 1a2 + 1a3
      // b1 = 1a0 + 2a1 + 3a2 + 1a3
      // b2 = 1a0 + 1a1 + 2a2 + 3a3
      // b3 = 3a0 + 1a1 + 1a2 + 2a3
      let a = block.slice(i, i + 4);
      let b = [
        MUL_02[a[0]] ^ MUL_03[a[1]] ^        a[2]  ^        a[3] ,
               a[0]  ^ MUL_02[a[1]] ^ MUL_03[a[2]] ^        a[3] ,
               a[0]  ^        a[1]  ^ MUL_02[a[2]] ^ MUL_03[a[3]],
        MUL_03[a[0]] ^        a[1]  ^        a[2]  ^ MUL_02[a[3]],
      ];

      block[i + 0] = b[0];
      block[i + 1] = b[1];
      block[i + 2] = b[2];
      block[i + 3] = b[3];
    }
  }

  MixColumnsReversed(block) {
    for(let i = 0 ; i < block.length ; i += 4) {
      // a0 = 14b0 + 11b1 + 13b2 +  9b3
      // a1 =  9b0 + 14b1 + 11b2 + 13b3
      // a2 = 13b0 +  9b1 + 14b2 + 11b3
      // a3 = 11b0 + 13b1 +  9b2 + 14b3
      let b = block.slice(i, i + 4);
      let a = [
        MUL_14[b[0]] ^ MUL_11[b[1]] ^ MUL_13[b[2]] ^ MUL_09[b[3]],
        MUL_09[b[0]] ^ MUL_14[b[1]] ^ MUL_11[b[2]] ^ MUL_13[b[3]],
        MUL_13[b[0]] ^ MUL_09[b[1]] ^ MUL_14[b[2]] ^ MUL_11[b[3]],
        MUL_11[b[0]] ^ MUL_13[b[1]] ^ MUL_09[b[2]] ^ MUL_14[b[3]],
      ];

      block[i + 0] = a[0];
      block[i + 1] = a[1];
      block[i + 2] = a[2];
      block[i + 3] = a[3];
    }
  }

  encrypt(_block) {
    let block = Utils.toArray(_block);

    let blockSize = block.length;
    let keySize = this.keySize;
    let roundCount = ROUNDS[blockSize][keySize];

    if(!SIZES.includes(blockSize))
      throw "Unsupported block size: " + (blockSize * 8) + "bit";

    // Calculations are made to this state
    let state = block.slice();

    // Key Expansion
    let expandedKey = this.ExpandKey(blockSize);

    // Initial Round
    this.AddRoundKey(state, expandedKey, 0);

    // Rounds
    for(let round = 1 ; round < roundCount ; round++) {
      this.SubBytes(state);
      this.ShiftRows(state);
      this.MixColumns(state);
      this.AddRoundKey(state, expandedKey, round);
    }

    // Final Round
    this.SubBytes(state);
    this.ShiftRows(state);
    this.AddRoundKey(state, expandedKey, roundCount);

    return state;
  }

  decrypt(_block) {
    let block = Utils.toArray(_block);

    let blockSize = block.length;
    let keySize = this.keySize;
    let roundCount = ROUNDS[blockSize][keySize];

    if(!SIZES.includes(blockSize))
      throw "Unsupported block size: " + (blockSize * 8) + "bit";

    // Calculations are made to this state
    let state = block.slice();

    // Key Expansion
    let expandedKey = this.ExpandKey(blockSize);

    // Final Round (Reversed)
    this.AddRoundKey(state, expandedKey, roundCount);
    this.ShiftRowsReversed(state);
    this.SubBytesReversed(state);

    // Rounds (Reversed)
    for(let round = roundCount - 1 ; 1 <= round ; round--) {
      this.AddRoundKey(state, expandedKey, round);
      this.MixColumnsReversed(state);
      this.ShiftRowsReversed(state);
      this.SubBytesReversed(state);
    }

    // Initial Round (Reversed)
    this.AddRoundKey(state, expandedKey, 0);

    return state;
  }
}

module.exports = Rijndael;
