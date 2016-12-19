"use strict";

module.exports.toArray = value => {
  if(Array.isArray(value)) return value.slice();
  else return [...Buffer.from(value)];
};
