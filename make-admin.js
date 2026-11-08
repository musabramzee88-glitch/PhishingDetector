// Usage: node make-admin.js <username>
// Prints an entry for the ADMINS env var. Add several admins separated by commas.
const c = require("node:crypto"), rl = require("node:readline").createInterface({ input: process.stdin, output: process.stdout });
const u = (process.argv[2] || "").toLowerCase();
if (!/^[a-z0-9_.-]{3,32}$/.test(u)) { console.log("Usage: node make-admin.js <username>  (a-z 0-9 _ . -)"); process.exit(1); }
rl.question("Password (min 12 chars): ", p => {
    rl.close();
    if (p.length < 12) { console.log("Too short."); process.exit(1); }
    const s = c.randomBytes(16).toString("hex");
    c.scrypt(p, s, 32, (e, k) => console.log("\nADMINS entry:\n" + u + ":" + s + ":" + k.toString("hex")));
});
