"use strict";

const crypto = require("crypto");

const Rijndael = require("../lib/rijndael-block");
const Mcrypt = require("mcrypt").MCrypt;

const TEST_COUNT = 100;

function runTest(size, blocks, mode, ivRequired = false, keySize = 256) {
  console.log("Running [Rijndael - Mcrypt] Comparison Test");
  console.log(`  Block Size - ${size} bit / Key Size - ${keySize} bit`);
  console.log(`  Blocks - ${blocks} / Mode - ${mode}`);
  let pass = true;
  let sizeByte = size / 8;
  let keySizeByte = keySize / 8;

  for(let i = 0 ; i < TEST_COUNT ; i++) {
    // Mcrypt uses 256 bit key by default
    let key = crypto.randomBytes(keySizeByte);
    let iv = crypto.randomBytes(sizeByte);
    let plaintext = crypto.randomBytes(sizeByte * blocks);

    // Test encryption
    {
      // Known implementation
      let known = new Mcrypt("rijndael-" + size, mode);
      known.open(key, iv);
      let expected = known.encrypt(plaintext).toString("hex");

      // Own implementation
      let cipher = new Rijndael(key, mode);
      let actual = cipher.encrypt(plaintext, size, iv).toString("hex");

      if(expected !== actual) {
        console.log("  Encryption Error");

        console.log("    Key       - " + key.toString("hex"));
        if(ivRequired) console.log("    IV        - " + iv.toString("hex"));
        console.log("    Plaintext - " + plaintext.toString("hex"));
        console.log("    Expected  - " + expected);
        console.log("    Actual    - " + actual);

        pass = false; process.exitCode = -1;
        break;
      }
    }

    // Test decryption
    {
      let known = new Mcrypt("rijndael-" + size, mode);
      known.open(key, iv);
      let expected = known.decrypt(plaintext).toString("hex");

      let cipher = new Rijndael(key, mode);
      let actual = cipher.decrypt(plaintext, size, iv).toString("hex");

      if(expected !== actual) {
        console.log("  Decryption Error");

        console.log("    Key       - " + key.toString("hex"));
        if(ivRequired) console.log("    IV        - " + iv.toString("hex"));
        console.log("    Ciphertext- " + plaintext.toString("hex"));
        console.log("    Expected  - " + expected);
        console.log("    Actual    - " + actual);

        pass = false; process.exitCode = -1;
        break;
      }
    }
  }

  console.log("  " + (pass ? "PASSED" : "FAILED"));
  return pass;
}

process.exitCode = 0;

// ECB Mode
//   rijndael-128
//   rijndael-192
//   rijndael-256
//   rijndael-(128|192|256) with 128 bit key
//   rijndael-(128|192|256) with 192 bit key
runTest(128,  1, "ecb", false);
runTest(128,  4, "ecb", false);
runTest(128, 16, "ecb", false);

runTest(192,  1, "ecb", false);
runTest(192,  4, "ecb", false);
runTest(192, 16, "ecb", false);

runTest(256,  1, "ecb", false);
runTest(256,  4, "ecb", false);
runTest(256, 16, "ecb", false);

runTest(128,  4, "ecb", false, 128);
runTest(192,  4, "ecb", false, 128);
runTest(256,  4, "ecb", false, 128);

runTest(128,  4, "ecb", false, 192);
runTest(192,  4, "ecb", false, 192);
runTest(256,  4, "ecb", false, 192);

// CBC Mode
//   rijndael-128
//   rijndael-192
//   rijndael-256
//   rijndael-(128|192|256) with 128 bit key
//   rijndael-(128|192|256) with 192 bit key
runTest(128,  1, "cbc", true);
runTest(128,  4, "cbc", true);
runTest(128, 16, "cbc", true);

runTest(192,  1, "cbc", true);
runTest(192,  4, "cbc", true);
runTest(192, 16, "cbc", true);

runTest(256,  1, "cbc", true);
runTest(256,  4, "cbc", true);
runTest(256, 16, "cbc", true);

runTest(128,  4, "cbc", true, 128);
runTest(192,  4, "cbc", true, 128);
runTest(256,  4, "cbc", true, 128);

runTest(128,  4, "cbc", true, 192);
runTest(192,  4, "cbc", true, 192);
runTest(256,  4, "cbc", true, 192);
