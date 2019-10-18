const fs = require('fs');
const path = require('path');

const Rijndael = require('../lib/rijndael');
const ParseNESSIE = require('./parse-nessie');

function runNessie(key, block) {
  console.log('Running Rijndael Test from NESSIE test vectors');
  console.log(`  Key Size - ${key} bit / Block Size - ${block} bit`);
  
  let pass = true;

  const nessieFile = path.join(__dirname, `data/k${key}-b${block}.txt`);
  const input = fs.readFileSync(nessieFile, { encoding: 'utf8' });
  const tests = ParseNESSIE(input);

  for (let test of tests) {
    const text = Buffer.from(test.plain, 'hex');
    const key = Buffer.from(test.key, 'hex');

    const rijndael = new Rijndael(key);

    // Test encryption
    let encrypted = rijndael.encrypt(text);
    encrypted = Buffer.from(encrypted);

    const expectedEncrypted = test.ciphertext;
    const actualEncrypted = encrypted.toString('hex');

    if (expectedEncrypted !== actualEncrypted) {
      console.log(`  Encryption Error at test <${test.name}>`);
      console.log(`    Expected - ${expectedEncrypted}`);
      console.log(`    Actual   - ${actualEncrypted}`);

      pass = false;
      process.exitCode = -1;
      break;
    }

    // Test decryption
    let decrypted = rijndael.decrypt(encrypted);
    decrypted = Buffer.from(decrypted);

    const expectedDecrypted = test.plain;
    const actualDecrypted = decrypted.toString('hex');

    if (expectedDecrypted !== actualDecrypted) {
      console.log(`  Decryption Error at test <${test.name}>`);
      console.log(`    Expected - ${expectedDecrypted}`);
      console.log(`    Actual   - ${actualDecrypted}`);

      pass = false;
      process.exitCode = -1;
      break;
    }
  }

  console.log(`  ${pass ? 'PASSED' : 'FAILED'}`);

  return pass;
}

process.exitCode = 0;

runNessie(128, 128);
runNessie(192, 128);
runNessie(256, 128);
runNessie(256, 192);
runNessie(256, 256);
