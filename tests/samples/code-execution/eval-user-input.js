// Malicious: evaluates user-controlled input
const userInput = process.argv[2];
const result = eval(userInput);
console.log(result);

// Also dangerous
const fn = new Function('return ' + userInput);
fn();

// setTimeout with string
setTimeout("alert('xss')", 1000);
