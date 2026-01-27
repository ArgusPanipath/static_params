module.exports = function entropy(str = "") {
  if (!str) return 0;

  const map = {};
  for (const char of str) {
    map[char] = (map[char] || 0) + 1;
  }

  let entropy = 0;
  const len = str.length;

  for (const char in map) {
    const p = map[char] / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
};
