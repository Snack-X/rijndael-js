const root = (
  (typeof self === 'object' && self.self === self && self) ||
  (typeof global === 'object' && global.global === global && global) ||
  this
);

const has = type => typeof root[type] !== 'undefined';
const is = (value, type) => has(type) && value instanceof root[type];

module.exports.toArray = data => {
  // if Buffer exists in global context, use Buffer
  if (has('Buffer')) {
    const buf = root.Buffer.from(data);
    return [...buf];
  }

  // TypedArray
  if (is(data, 'TypedArray')) {
    const u8 = new Uint8Array(data.buffer);
    return [...u8];
  }

  // string
  if (typeof data === 'string') {
    const bytestring = unescape(encodeURIComponent(data));
    return [...bytestring].map(c => c.charCodeAt(0));
  }

  // other array-like objects
  const arr = Array.from(data);

  for (let i = 0; i < arr.length; i++) {
    const b = arr[i];

    if (!Number.isInteger(b) || b < 0x00 || 0xff < b)
      throw new Error(`Given data is not a byte array (data[${i}] = ${b}))`);
  }

  return arr;
};
