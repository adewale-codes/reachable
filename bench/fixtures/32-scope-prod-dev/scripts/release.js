const argv = require('minimist')(process.argv.slice(2));

console.log(`releasing ${argv.tag}`);
