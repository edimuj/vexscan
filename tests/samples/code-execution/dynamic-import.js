// Dynamic require from user input - dangerous
const moduleName = getUserInput();
const maliciousModule = require(moduleName);

// Dynamic import
const mod = await import(userControlledPath);

// vm module abuse
const vm = require('vm');
vm.runInThisContext(untrustedCode);
