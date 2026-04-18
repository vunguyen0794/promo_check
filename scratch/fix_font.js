const fs = require('fs');
let code = fs.readFileSync('server.js', 'utf8');
code = code.replace(
    /if \(n >= 1_000_000_000\) return \(n \/ 1_000_000_000\)\.toFixed\(2\)\.replace\(\/\\\.00\$\/, ''\) \+ ' Tá»·';/,
    "if (n >= 1_000_000_000) return (n / 1_000_000_000).toFixed(2).replace(/\\\\.00$$/, '') + ' Tỷ ₫';"
);
code = code.replace(
    /if \(n >= 1_000_000\) return \(n \/ 1_000_000\)\.toFixed\(1\)\.replace\(\/\\\.0\$\/, ''\) \+ ' Tr';/,
    "if (n >= 1_000_000) return (n / 1_000_000).toFixed(1).replace(/\\\\.0$$/, '') + ' Tr ₫';"
);
code = code.replace(
    /if \(n >= 1_000\) return \(n \/ 1_000\)\.toFixed\(1\)\.replace\(\/\\\.0\$\/, ''\) \+ ' K';/,
    "if (n >= 1_000) return (n / 1_000).toFixed(1).replace(/\\\\.0$$/, '') + ' K ₫';"
);
fs.writeFileSync('server.js', code);
