// Download URL policy for store-msix-fetch.mjs, kept apart so it can be tested
// without network (store-msix-url.test.mjs). Applied to the URL FE3 returns and
// to every redirect Location before any request is sent.

const ALLOWED_DOMAIN = 'delivery.mp.microsoft.com';

// Resolves raw against base (for relative redirects) and returns the absolute
// URL. Throws unless it is https, has no userinfo, its host is
// delivery.mp.microsoft.com or a subdomain of it, and its port is the default
// (443).
export function checkDownloadUrl(raw, base) {
  let u;
  try { u = new URL(raw, base); } catch { throw new Error('download URL does not parse'); }
  if (u.protocol !== 'https:') throw new Error(`download URL scheme ${u.protocol} is not https:`);
  if (u.username || u.password) throw new Error('download URL carries credentials');
  const h = u.hostname;
  if (h !== ALLOWED_DOMAIN && !h.endsWith(`.${ALLOWED_DOMAIN}`)) throw new Error(`download host ${h} is not under ${ALLOWED_DOMAIN}`);
  if (u.port !== '' && u.port !== '443') throw new Error(`download port ${u.port} is not 443`);
  return u.href;
}

// FE3 hands out the package URL as plain http (seen on tlu.dl.delivery.mp.
// microsoft.com, 2026-11). That one URL is moved to https on the same host and
// path before the check; with an explicit port it stays http and is rejected.
// Redirect Locations are never upgraded: they must already pass
// checkDownloadUrl.
export function fe3DownloadUrl(raw) {
  let u;
  try { u = new URL(raw); } catch { throw new Error('download URL does not parse'); }
  if (u.username || u.password) throw new Error('download URL carries credentials');
  if (u.protocol === 'http:' && u.port === '') u = new URL(`https://${u.hostname}${u.pathname}${u.search}`);
  return checkDownloadUrl(u.href);
}
