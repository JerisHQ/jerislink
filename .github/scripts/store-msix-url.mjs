// Download URL policy for store-msix-fetch.mjs, kept apart so it can be tested
// without network (store-msix-url.test.mjs). Applied to the URL FE3 returns and
// to every redirect Location, before any request is sent.
//
// Why plain http is allowed at all: Microsoft serves Store packages from
// *.dl.delivery.mp.microsoft.com over http only. FE3 returns the URL as
// http://tlu.dl.delivery.mp.microsoft.com/..., and https on these hosts gets a
// CDN certificate for another name (checked 2026-11-23 from a GitHub runner,
// a Linux container and macOS: ERR_TLS_CERT_ALTNAME_INVALID). Windows Update
// itself downloads this content over http and relies on hashes. So does this
// script: the URL comes from FE3 over TLS pinned to Microsoft Root CA 2011, the
// file must equal the SHA-256 and size DCAT gave over system TLS, and the
// verify job then checks Authenticode and the Microsoft root. A changed file
// on the wire fails those checks; it cannot be uploaded.
//
// What is enforced on every hop (the FE3 URL and each redirect):
// - host delivery.mp.microsoft.com or a subdomain of it;
// - scheme https on port 443, or http on port 80 (default ports only);
// - no userinfo;
// - no downgrade: http:80 is allowed only while the chain is still http, that
//   is, only when the FE3 URL itself is http. Once a hop is https, every later
//   hop must be https:443. An http FE3 URL may still redirect to https or to
//   another allowlisted http:80 URL.

const ALLOWED_DOMAIN = 'delivery.mp.microsoft.com';
const DEFAULT_PORT = { 'https:': '443', 'http:': '80' };

// Resolves raw against base (for relative redirects) and returns the absolute
// URL, or throws if the policy above is not met. base is the URL of the hop
// that sent the redirect (undefined for the FE3 URL). Each hop is checked
// against the one before it, so "https once, https from then on" holds for
// the whole chain.
export function checkDownloadUrl(raw, base) {
  let u;
  try { u = new URL(raw, base); } catch { throw new Error('download URL does not parse'); }
  if (!(u.protocol in DEFAULT_PORT)) throw new Error(`download URL scheme ${u.protocol} is not https: or http:`);
  if (u.username || u.password) throw new Error('download URL carries credentials');
  const h = u.hostname;
  if (h !== ALLOWED_DOMAIN && !h.endsWith(`.${ALLOWED_DOMAIN}`)) throw new Error(`download host ${h} is not under ${ALLOWED_DOMAIN}`);
  // WHATWG URL drops a port equal to the scheme default, so any port left is
  // a non-default one (http:443 and https:80 included).
  if (u.port !== '' && u.port !== DEFAULT_PORT[u.protocol]) throw new Error(`download port ${u.port} is not the ${u.protocol} default ${DEFAULT_PORT[u.protocol]}`);
  if (base !== undefined && new URL(base).protocol === 'https:' && u.protocol !== 'https:') {
    throw new Error(`download redirect from https: to ${u.protocol} refused (no downgrade)`);
  }
  return u.href;
}
