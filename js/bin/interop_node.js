// The JS driver for the language-agnostic interop harness (interop/). Implements
// the neutral driver contract (keygen / listen / connect) over shared,
// implementation-independent key and certificate files, so the harness pairs it
// with any other driver. The node private key is stored as opaque PKCS#8 DER
// (base64); it never crosses a node boundary, so its format is this driver's own.
import fs from 'node:fs';
import { Node } from '../src/node.js';
import { mldsa65Generate } from '../src/crypto.js';

const [, , mode, ...rest] = process.argv;
const f = parseFlags(rest);

switch (mode) {
  case 'keygen': keygen(); break;
  case 'listen': await listen(); break;
  case 'connect': await connect(); break;
  case 'mesh': await mesh(); break;
  default:
    process.stderr.write('usage: interop_node <keygen|listen|connect> [--flag value ...]\n');
    process.exit(2);
}

function keygen() {
  const { pub, priv } = mldsa65Generate();
  fs.writeFileSync(f['id-pub'], Buffer.from(pub).toString('base64'));
  fs.writeFileSync(f['id-priv'], priv.toString('base64'));
}

function config() {
  const rootPublic = Buffer.from(read(f['root-pub']).trim(), 'base64');
  const idPrivate = Buffer.from(read(f['id-priv']).trim(), 'base64');
  const cert = JSON.parse(read(f['cert']));
  return { label: cert.label, mesh: f.mesh, rootPublic, cert, idPrivate };
}

async function listen() {
  const node = await Node.start(config(), Number(f.port));
  node.onMessage((payload) => fs.appendFileSync(f.out, JSON.stringify(payload) + '\n'));
  await sleep(seconds() * 1000);
  node.kill();
  process.exit(0);
}

async function connect() {
  const node = await Node.start(config(), 0);
  try {
    await node.connect(f.host, Number(f.port));
  } catch (e) {
    process.stderr.write('connect: ' + e.message + '\n');
    process.exit(1);
  }
  const payload = JSON.parse(read(f.message));
  const deadline = Date.now() + seconds() * 1000;
  while (Date.now() < deadline) {
    if (node.send(f.to, payload)) break;
    await sleep(200);
  }
  await sleep(1500);
  node.kill();
  process.exit(0);
}

// The multi-link mode for the convergence tier: dial several --peers
// (host:port,host:port), optionally log delivered payloads (--out), repeatedly
// send toward a routed destination (--send-to with --message), and periodically
// dump the routing table (--routes). Stays up for --seconds.
async function mesh() {
  const node = await Node.start(config(), Number(f.port || 0));
  if (f.out) node.onMessage((payload) => fs.appendFileSync(f.out, JSON.stringify(payload) + '\n'));
  for (const peer of (f.peers || '').split(',').filter(Boolean)) {
    const c = peer.lastIndexOf(':');
    await node.connect(peer.slice(0, c), Number(peer.slice(c + 1)));
  }
  const payload = f.message ? JSON.parse(read(f.message)) : null;
  const deadline = Date.now() + seconds() * 1000;
  while (Date.now() < deadline) {
    if (f['send-to'] && payload) node.send(f['send-to'], payload);
    if (f.routes) fs.writeFileSync(f.routes, JSON.stringify(node.routeTable()));
    await sleep(500);
  }
  node.kill();
  process.exit(0);
}

function parseFlags(args) {
  const m = {};
  for (let i = 0; i + 1 < args.length; i += 2) {
    if (args[i].startsWith('--')) m[args[i].slice(2)] = args[i + 1];
  }
  return m;
}

function read(path) { return fs.readFileSync(path, 'utf8'); }
function seconds() { return f.seconds ? Number(f.seconds) : 10; }
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
