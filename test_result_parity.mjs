// test_result_parity.mjs — reverse direction of the E2EE result channel:
// proves the showResult() calls in approve_server.py's APP_JS decrypt what
// approve_client.seal_payload() produced.
// usage:
//   node test_result_parity.mjs gen                      -> {"spki":..., "jwk":{...}}
//   node test_result_parity.mjs open <jwk_json> <sealed> -> plaintext json
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

if (process.argv[2] === 'gen') {
  // identical sequence to APPJS approve() result-key generation:
  const rk = await crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, hash: 'SHA-256',
      publicExponent: new Uint8Array([1, 0, 1]) }, true,
    ['encrypt', 'decrypt']);
  console.log(JSON.stringify({
    spki: B64.bytesToB64(await crypto.subtle.exportKey('spki', rk.publicKey)),
    jwk: await crypto.subtle.exportKey('jwk', rk.privateKey) }));
  process.exit(0);
}

if (process.argv[2] === 'open') {
  // identical sequence to APPJS showResult():
  const prv = await crypto.subtle.importKey('jwk', JSON.parse(process.argv[3]),
    { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
  const sealed = JSON.parse(process.argv[4]);
  const aesRaw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, prv,
    B64.urlToBytes(sealed.ek));
  const aesKey = await crypto.subtle.importKey('raw', aesRaw,
    { name: 'AES-GCM' }, false, ['decrypt']);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: B64.urlToBytes(sealed.iv) }, aesKey,
    B64.urlToBytes(sealed.ct));
  console.log(new TextDecoder().decode(plain));
  process.exit(0);
}

console.error('usage: node test_result_parity.mjs gen | open <jwk> <sealed>');
process.exit(2);
