// This is an dirty and stupid parser of NESSIE Test Vector File
// https://www.cosic.esat.kuleuven.be/nessie/testvectors/

module.exports = function (text) {
  const r1 = 'Set (\\d+), vector#\\s+(\\d+):';
  const r2 = '\\s+(.+)=((?:[0-9a-f]{48}|[0-9a-f]{32})(?:\\s+[0-9a-f]{32})?)';
  const matchRegex = new RegExp(`${r1}[\\r\\n]+(?:${r2}[\\r\\n]+)+`, 'ig');

  const matches = text.match(matchRegex);
  const tests = [];

  for (const match of matches) {
    const test = {};

    const nameMatch = match.match(new RegExp(r1, 'i'));
    test.name = `set-${nameMatch[1]}-vector-${nameMatch[2]}`;

    const dataMatches = match.match(new RegExp(r2, 'ig'));

    for (const line of dataMatches) {
      const lineMatch = line.match(new RegExp(r2, 'i'));

      if (lineMatch[1].toLowerCase() === 'key')
        test.key = lineMatch[2].replace(/\s/g, '').toLowerCase();
      if (lineMatch[1].toLowerCase() === 'plain')
        test.plain = lineMatch[2].replace(/\s/g, '').toLowerCase();
      if (lineMatch[1].toLowerCase() === 'cipher')
        test.ciphertext = lineMatch[2].replace(/\s/g, '').toLowerCase();
    }

    tests.push(test);
  }

  return tests;
};
