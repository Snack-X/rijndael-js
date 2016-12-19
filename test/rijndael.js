"use strict";

const fs = require("fs");
const path = require("path");

const Rijndael = require("../lib/rijndael");
const ParseNESSIE = require("./parse-nessie");

function runNessie(key, block) {
  console.log("Running Rijndael Test from NESSIE test vectors");
  console.log(`  Key Size - ${key} bit / Block Size - ${block} bit`);
  let pass = true;

  let nessieFile = path.join(__dirname, `data/k${key}-b${block}.txt`);
  let input = fs.readFileSync(nessieFile, { encoding: "utf8" });
  let tests = ParseNESSIE(input);

  for(let test of tests) {
    let text = Buffer.from(test.plain, "hex");
    let key = Buffer.from(test.key, "hex");

    let rijndael = new Rijndael(key);

    // Test encryption
    let encrypted = rijndael.encrypt(text);
    encrypted = Buffer.from(encrypted);

    let expectedEncrypted = test.ciphertext;
    let actualEncrypted = encrypted.toString("hex");

    if(expectedEncrypted !== actualEncrypted) {
      console.log("  Encryption Error at test <" + test.name + ">");
      console.log("    Expected - " + expectedEncrypted);
      console.log("    Actual   - " + actualEncrypted);

      pass = false; process.exitCode = -1;
      break;
    }

    // Test decryption
    let decrypted = rijndael.decrypt(encrypted);
    decrypted = Buffer.from(decrypted);

    let expectedDecrypted = test.plain;
    let actualDecrypted = decrypted.toString("hex");

    if(expectedDecrypted !== actualDecrypted) {
      console.log("  Decryption Error at test <" + test.name + ">");
      console.log("    Expected - " + expectedDecrypted);
      console.log("    Actual   - " + actualDecrypted);

      pass = false; process.exitCode = -1;
      break;
    }
  }

  console.log("  " + (pass ? "PASSED" : "FAILED"));
  return pass;
}

process.exitCode = 0;

runNessie(128, 128);
runNessie(192, 128);
runNessie(256, 128);
runNessie(256, 192);
runNessie(256, 256);
