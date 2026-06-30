// KnoSky airgap shim — loaded via `node --import`. Any network use throws + logs AIRGAP-VIOLATION.
// Defensive: per-patch try/catch (+ defineProperty fallback) so a single non-writable builtin
// export cannot abort the preload. Socket.prototype.connect is the reliable comprehensive TCP catch.
import { createRequire } from 'node:module';
import { Socket } from 'node:net';
const require = createRequire(import.meta.url);
const trip = (which) => function () {
  process.stderr.write('AIRGAP-VIOLATION: ' + which + '\n');
  throw new Error('AIRGAP-VIOLATION: ' + which);
};
const patch = (obj, prop, which) => {
  if (!obj) return;
  try { obj[prop] = trip(which); }
  catch { try { Object.defineProperty(obj, prop, { value: trip(which), configurable: true, writable: true }); } catch {} }
};
patch(Socket.prototype, 'connect', 'net.Socket.prototype.connect');
const net = require('node:net');     patch(net, 'connect', 'net.connect'); patch(net, 'createConnection', 'net.createConnection');
const dns = require('node:dns');     patch(dns, 'lookup', 'dns.lookup'); patch(dns, 'resolve', 'dns.resolve'); if (dns.promises) patch(dns.promises, 'lookup', 'dns.promises.lookup');
const http = require('node:http');   patch(http, 'request', 'http.request'); patch(http, 'get', 'http.get');
const https = require('node:https'); patch(https, 'request', 'https.request'); patch(https, 'get', 'https.get');
const tls = require('node:tls');     patch(tls, 'connect', 'tls.connect');