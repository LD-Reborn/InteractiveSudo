// test_page_parity.mjs — proves the browser-side crypto (exactly the calls
// in approve_server.py's APP_JS) interoperates with approve_client.py.
// usage: node test_page_parity.mjs <spki_b64url> [payload_b64url(json)]
//        (payload defaults to a fixed test blob) -> prints {ek,iv,ct} json
const spki = process.argv[2];
if (!spki) { console.error('usage: node test_page_parity.mjs <spki> [payload_b64url]'); process.exit(2); }

const pad = s => s + '='.repeat((4 - s.length % 4) % 4);
const B64 = {
  urlToBytes(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(pad(s)); const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  },
  bytesToB64(b) {
    let s = ''; const u = new Uint8Array(b);
    for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
};

const payload = process.argv[3]
  ? JSON.parse(new TextDecoder().decode(B64.urlToBytes(process.argv[3])))
  : { v: 1, id: 'test-req-1', password: 'hunter2 testgeheim',
      secrets: { GIT_TOKEN: 'tok-with-$pecial välu' },
      scope: 'once', ts: Math.floor(Date.now() / 1000) };

// identical sequence to APPJS approve():
const pub = await crypto.subtle.importKey('spki', B64.urlToBytes(spki),
  { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
const aesKey = await crypto.subtle.generateKey(
  { name: 'AES-GCM', length: 256 }, true, ['encrypt']);
const iv = crypto.getRandomValues(new Uint8Array(12));
const plain = new TextEncoder().encode(JSON.stringify(payload));
const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plain);
const raw = await crypto.subtle.exportKey('raw', aesKey);
const ek = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, raw);

console.log(JSON.stringify({
  ek: B64.bytesToB64(ek), iv: B64.bytesToB64(iv), ct: B64.bytesToB64(ct) }));
