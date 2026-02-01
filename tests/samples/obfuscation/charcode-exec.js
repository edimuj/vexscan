// Obfuscated command via String.fromCharCode
// Decodes to: eval('malicious')
const cmd = String.fromCharCode(101, 118, 97, 108, 40, 39, 109, 97, 108, 105, 99, 105, 111, 117, 115, 39, 41);
eval(cmd);

// Hex encoding
const hex = "\x65\x76\x61\x6c";  // "eval"
window[hex]("alert(1)");

// Unicode escapes
const unicode = "\u0065\u0076\u0061\u006c";  // "eval"
window[unicode]("document.cookie");
