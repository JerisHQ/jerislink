// Downloads the Microsoft Store-signed x64 MSIX of a Store product and checks
// it against the Store catalog before anything else may use it.
//
// 1. DCAT (displaycatalog.mp.microsoft.com, normal system TLS): the x64 package
//    of the expected family, with its version, SHA-256 and size.
// 2. FE3 (fe3.delivery.mp.microsoft.com): GetCookie, SyncUpdates, then
//    GetExtendedUpdateInfo2 on /secured for the download URL. FE3's TLS chain
//    ends at Microsoft Root Certificate Authority 2011, which Linux CA bundles
//    do not carry, so FE3 requests trust exactly that root (embedded below,
//    fingerprint checked at start-up) and nothing else.
// 3. Download. The FE3 URL and every redirect hop must be on a
//    delivery.mp.microsoft.com host, https:443 or http:80, no userinfo
//    (store-msix-url.mjs, which also says why plain http is allowed); the
//    request is not sent otherwise. The file is accepted only if its size and
//    SHA-256 equal the DCAT values; otherwise nothing is written and the script
//    exits non-zero.
//
// Signature, identity and version-vs-tag checks run afterwards on Windows
// (store-msix-to-release.yml, job verify).
//
// Usage: node store-msix-fetch.mjs <productId> <packageFamilyName> <outDir>
// Writes <outDir>/store.msix and <outDir>/dcat.json, prints key=value lines
// (version, sha256, size, full_name) for $GITHUB_OUTPUT on stdout's last lines.
// No secrets are used or needed.

import https from 'node:https';
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { checkDownloadUrl } from './store-msix-url.mjs';

const [productId, familyName, outDir] = process.argv.slice(2);
if (!/^[0-9A-Z]{12}$/.test(productId ?? '') || !/^[\w.-]+_[a-z0-9]{13}$/.test(familyName ?? '') || !outDir) {
  fail('usage: store-msix-fetch.mjs <productId> <packageFamilyName> <outDir>');
}
const ARCH = 'x64';
const MAX_BYTES = 512 * 1024 * 1024;

// Microsoft Root Certificate Authority 2011
// (http://www.microsoft.com/pki/certs/MicRooCerAut2011_2011_03_22.crt).
const MS_ROOT_2011_SHA256 = '847DF6A78497943F27FC72EB93F9A637320A02B561D0A91B09E87A7807ED7C61';
const MS_ROOT_2011_PEM = `-----BEGIN CERTIFICATE-----
MIIF7TCCA9WgAwIBAgIQP4vItfyfspZDtWnWbELhRDANBgkqhkiG9w0BAQsFADCB
iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMp
TWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEw
MzIyMjIwNTI4WhcNMzYwMzIyMjIxMzA0WjCBiDELMAkGA1UEBhMCVVMxEzARBgNV
BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
aWNhdGUgQXV0aG9yaXR5IDIwMTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQCygEGqNThNE3IyaCJNuLLx/9VSvGzH9dJKjDbu0cJcfoyKrq8TKG/Ac+M6
ztAlqFo6be+ouFmrEyNozQwph9FvgFyPRH9dkAFSWKxRxV8qh9zc2AodwQO5e7BW
6KPeZGHCnvjzfLnsDbVU/ky2ZU+I8JxImQxCCwl8MVkXeQZ4KI2JOkwDJb5xalwL
54RgpJki49KvhKSn+9GY7Qyp3pSJ4Q6g3MDOmT3qCFK7VnnkH4S6Hri0xElcTzFL
h93dBWcmmYDgcRGjuKVB4qRTufcyKYMME782XgSzS0NHL2vikR7TmE/dQgfI6B0S
/Jmpaz6SfsjWaTr8ZL22CZ3K/QwLopt3YEsDlKQwaRLWQi3BQUzK3Kr9j1uDRprZ
/LHR47PJf0h6zSTwQY9cdNCssBAgBkm3xy0hyFfj0IbzA2j70M5xwYmZSmQBbP3s
MJHPQTySx+W6hh1hhMdfgzlirrSSL0fzC/hV66AfWdC7dJse0Hbm8ukG1xDo+mTe
acY1logC8Ea4PyeZb8txiSk190gWAjWP1Xl8TQLPX+uKg09FcYj5qQ1OcunCnAfP
SRtOBA5jUYxe2ADBVSy2xuDCZU7JNDn1nLPEfuhhbhNfFcRf2X7tHc7uROzLLoax
7Dj2cO2rXBPB2Q8Nx4CyVe0096yb5MPa50c8prWPMd/FS6/r8QIDAQABo1EwTzAL
BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUci06AjGQQ7kU
BU7h6qfHMdEjiTQwEAYJKwYBBAGCNxUBBAMCAQAwDQYJKoZIhvcNAQELBQADggIB
AH9yzw+3xRXbm8BJyiZb/p4T5tPw0tuXX/JLP02zrhmu7deXoKzvqTqjwkGw5biR
nhOBJAPmCf0/V0A5ISRW0RAvS0CpNoZLtFNXmvvxfomPEf4YbFGq6O0JlbXlccmh
6Yd1phV/yX43VF50k8XDZ8wNT2uoFwxtCJJ+i92Bqi1wIcM9BhS7vyRep4TXPw8h
Ir1LAAbblxzYXtTFC1yHblCk6MM4pPvLLMWSZpuFXst6bJN8gClYW1e1QGm6CHmm
ZGIVnYeWRbVmIyADixxzoNOieTPgUFmG2y/lAiXqcyqfABTINseSO+lOAOzYVgm5
M0kS0lQLAausR7aRKX1MtHWAUgHoyoL2n8ysnI8X6i8msKtyrAv+nlEex0NVZ09R
s1fWtuzuUrc66U7h14GIvE+OdbtLqPA1qibUZ2dJsnBMO5PcHd94kIZysjik0dyS
TclY6ysSXNQ7roxrsIPlAT/4CTL2kzU0Iq/dNw13CYArzUgA8YyZGUcFAenRv9FO
0OYoQzeZpApKCNmacXPSqs0xE2N2oTdvkjgefRI8ZjLny23h/FKJ3crWZgWalmG+
oijHHKOnNlA8OqTfSm7mhzvO6/DggTedEzxSjr25HTTGHdUKaj2YKXCMiSrRq4IQ
SB/c9O+lxbtVGjhjhE63bK2VVOxlIhBJF7jAHscPrFRH
-----END CERTIFICATE-----`;

function downloadUrl(raw, base) {
  try { return checkDownloadUrl(raw, base); } catch (e) { fail(e.message); }
}

function fail(msg) { console.error(`::error::${msg}`); process.exit(1); }
function log(msg) { console.error(msg); }

const root = new crypto.X509Certificate(MS_ROOT_2011_PEM);
if (root.fingerprint256.replaceAll(':', '') !== MS_ROOT_2011_SHA256) fail('embedded Microsoft root fingerprint mismatch');
const fe3Agent = new https.Agent({ ca: [MS_ROOT_2011_PEM], keepAlive: false });

function request(url, { method = 'GET', body, headers = {}, agent, limit = 32 * 1024 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : u.protocol === 'http:' ? http : null;
    if (!mod) return reject(new Error(`unsupported scheme ${u.protocol}`));
    const req = mod.request(u, { method, headers, agent, timeout: 60_000 }, res => {
      const chunks = []; let n = 0;
      res.on('data', c => { n += c.length; if (n > limit) { req.destroy(new Error('response too large')); return; } chunks.push(c); });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

const xmlUnescape = s => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
const attr = (s, name) => (s.match(new RegExp(`\\b${name}="([^"]*)"`)) || [])[1];
const blocks = (s, tag) => [...s.matchAll(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`, 'g'))].map(m => m[1]);

// ---- 1. DCAT -------------------------------------------------------------
const dcatUrl = `https://displaycatalog.mp.microsoft.com/v7.0/products/${productId}?market=US&languages=en-US,en,neutral`;
const dcatRes = await request(dcatUrl);
if (dcatRes.status !== 200) fail(`DCAT HTTP ${dcatRes.status}`);
const dcat = JSON.parse(dcatRes.body.toString('utf8'));
const skus = dcat?.Product?.DisplaySkuAvailabilities ?? [];
const wuCats = new Set(skus.map(a => a.Sku?.Properties?.FulfillmentData?.WuCategoryId).filter(Boolean));
if (wuCats.size !== 1) fail(`expected one WuCategoryId, found ${wuCats.size}`);
const wuCategoryId = [...wuCats][0];
const pkgs = new Map();
for (const a of skus) for (const p of a.Sku?.Properties?.Packages ?? []) {
  if (p.PackageFamilyName !== familyName) continue;
  if (JSON.stringify(p.Architectures) !== JSON.stringify([ARCH])) continue;
  if (String(p.PackageFormat).toLowerCase() !== 'msix') continue;
  pkgs.set(p.PackageFullName, p);
}
if (pkgs.size !== 1) fail(`expected one ${ARCH} MSIX of ${familyName} in DCAT, found ${pkgs.size}: ${[...pkgs.keys()].join(', ')}`);
const pkg = [...pkgs.values()][0];
if (pkg.HashAlgorithm !== 'SHA256') fail(`DCAT HashAlgorithm is ${pkg.HashAlgorithm}`);
const expSha = Buffer.from(pkg.Hash, 'base64');
if (expSha.length !== 32) fail('DCAT Hash is not a SHA-256');
const expSize = Number(pkg.MaxDownloadSizeInBytes);
if (!Number.isSafeInteger(expSize) || expSize <= 0 || expSize > MAX_BYTES) fail(`bad DCAT size ${pkg.MaxDownloadSizeInBytes}`);
const v = BigInt(pkg.Version);
const version = [48n, 32n, 16n, 0n].map(s => String((v >> s) & 0xffffn)).join('.');
const fullName = pkg.PackageFullName;
const parts = fullName.split('_');
if (parts.length !== 5 || `${parts[0]}_${parts[4]}` !== familyName || parts[1] !== version || parts[2] !== ARCH) {
  fail(`PackageFullName ${fullName} does not match family/version/arch`);
}
const expShaHex = expSha.toString('hex');
log(`DCAT: ${fullName} version=${version} size=${expSize} sha256=${expShaHex} wuCategory=${wuCategoryId}`);

// ---- 2. FE3 --------------------------------------------------------------
const FE3 = 'https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx';
const now = new Date(), later = new Date(now.getTime() + 5 * 60_000);
const security = to => `<a:To s:mustUnderstand="1">${to}</a:To>
<o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
<Timestamp xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><Created>${now.toISOString()}</Created><Expires>${later.toISOString()}</Expires></Timestamp>
<wuws:WindowsUpdateTicketsToken wsu:id="ClientMSA" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wuws="http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization"><TicketType Name="MSA" Version="1.0" Policy="MBI_SSL"><User/></TicketType></wuws:WindowsUpdateTicketsToken>
</o:Security>`;
const envelope = (action, to, body) => `<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header>
<a:Action s:mustUnderstand="1">http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/${action}</a:Action>
<a:MessageID>urn:uuid:${randomUUID()}</a:MessageID>
${security(to)}
</s:Header><s:Body>${body}</s:Body></s:Envelope>`;
const DEVICE = 'BranchReadinessLevel=CB;CurrentBranch=rs_prerelease;OEMModel=Virtual Machine;FlightRing=WIS;AttrDataVer=21;SystemManufacturer=Microsoft Corporation;InstallLanguage=en-US;OSUILocale=en-US;InstallationType=Client;FlightingBranchName=external;FirmwareVersion=Hyper-V UEFI Release v2.5;SystemProductName=Virtual Machine;OSSkuId=48;FlightContent=Branch;App=WU;OEMName_Uncleaned=Microsoft Corporation;AppVer=10.0.16184.1001;OSArchitecture=AMD64;SystemSKU=None;UpdateManagementGroup=2;IsFlightingEnabled=1;IsDeviceRetailDemo=0;TelemetryLevel=3;OSVersion=10.0.16184.1001;DeviceFamily=Windows.Desktop;';

async function fe3(url, action, body) {
  const r = await request(url, { method: 'POST', agent: fe3Agent, body: envelope(action, url, body),
    headers: { 'Content-Type': 'application/soap+xml; charset=utf-8', 'User-Agent': 'jerislink-store-msix-fetch' } });
  if (r.status !== 200) fail(`FE3 ${action} HTTP ${r.status}`);
  return r.body.toString('utf8');
}

const cookieXml = await fe3(FE3, 'GetCookie', `<GetCookie xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService"><oldCookie></oldCookie><lastChange>2015-10-21T17:01:07.1472913Z</lastChange><currentTime>${now.toISOString()}</currentTime><protocolVersion>1.40</protocolVersion></GetCookie>`);
// The cookie for later calls is exactly what GetCookie returned: its
// Expiration and EncryptedData, checked for shape, never made up.
const cookieExp = (cookieXml.match(/<Expiration>([^<]+)<\/Expiration>/) || [])[1];
const cookie = (cookieXml.match(/<EncryptedData>([^<]+)<\/EncryptedData>/) || [])[1];
if (!cookie || !/^[A-Za-z0-9+/=]+$/.test(cookie)) fail('FE3 GetCookie: no usable EncryptedData');
if (!cookieExp || !/^\d{4}-\d\d-\d\dT[\d:.]+Z?$/.test(cookieExp) || Number.isNaN(Date.parse(cookieExp))) fail('FE3 GetCookie: no usable Expiration');

const syncXml = xmlUnescape(await fe3(FE3, 'SyncUpdates', `<SyncUpdates xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">
<cookie><Expiration>${cookieExp}</Expiration><EncryptedData>${cookie}</EncryptedData></cookie>
<parameters><ExpressQuery>false</ExpressQuery><InstalledNonLeafUpdateIDs><int>1</int><int>2</int><int>3</int><int>11</int><int>19</int><int>544</int><int>549</int><int>2359974</int><int>2359977</int><int>5169044</int><int>8788830</int><int>23110993</int><int>23110994</int><int>54341900</int><int>54343656</int><int>59830006</int><int>59830007</int><int>59830008</int><int>60484010</int><int>62450018</int><int>62450019</int><int>62450020</int><int>66027979</int><int>66053150</int><int>97657898</int><int>98822896</int><int>98959022</int><int>98959023</int><int>98959024</int><int>98959025</int><int>98959026</int><int>104433538</int><int>104900364</int><int>105489019</int><int>117765322</int><int>129905029</int><int>130040031</int><int>132387090</int><int>132393049</int><int>133399034</int><int>138537048</int><int>140377312</int><int>143747671</int><int>158941041</int><int>158941042</int><int>158941043</int><int>158941044</int><int>159123858</int><int>159130928</int><int>164836897</int><int>164847386</int><int>164848327</int><int>164852241</int><int>164852246</int><int>164852252</int><int>164852253</int></InstalledNonLeafUpdateIDs>
<SkipSoftwareSync>false</SkipSoftwareSync><NeedTwoGroupOutOfScopeUpdates>true</NeedTwoGroupOutOfScopeUpdates>
<FilterAppCategoryIds><CategoryIdentifier><Id>${wuCategoryId}</Id></CategoryIdentifier></FilterAppCategoryIds>
<TreatAppCategoryIdsAsInstalled>true</TreatAppCategoryIdsAsInstalled><AlsoPerformRegularSync>false</AlsoPerformRegularSync><ComputerSpec/>
<ExtendedUpdateInfoParameters><XmlUpdateFragmentTypes><XmlUpdateFragmentType>Extended</XmlUpdateFragmentType></XmlUpdateFragmentTypes><Locales><string>en-US</string><string>en</string></Locales></ExtendedUpdateInfoParameters>
<ClientPreferredLanguages><string>en-US</string></ClientPreferredLanguages>
<ProductsParameters><SyncCurrentVersionOnly>false</SyncCurrentVersionOnly><DeviceAttributes>${DEVICE}</DeviceAttributes><CallerAttributes>Interactive=1;IsSeeker=0;</CallerAttributes><Products/></ProductsParameters>
</parameters></SyncUpdates>`));

// The ExtendedUpdateInfo entry whose File InstallerSpecificIdentifier is our
// PackageFullName gives the internal ID and the file's SHA-1 digest; the
// UpdateInfo entry with that ID (and a SecuredFragment) gives UpdateID/Revision.
let match = null;
for (const u of blocks(syncXml, 'Update')) {
  const id = (u.match(/<ID>(\d+)<\/ID>/) || [])[1];
  for (const f of u.match(/<File [^>]*>/g) ?? []) {
    if (attr(f, 'InstallerSpecificIdentifier') === fullName) {
      if (match && match.id !== id) fail(`FE3: ${fullName} appears in more than one update`);
      match = { id, digest: attr(f, 'Digest'), fileName: attr(f, 'FileName'), size: attr(f, 'Size') };
    }
  }
}
if (!match) fail(`FE3 SyncUpdates did not list ${fullName}`);
const info = blocks(syncXml, 'UpdateInfo').find(u => (u.match(/<ID>(\d+)<\/ID>/) || [])[1] === match.id && u.includes('SecuredFragment'));
if (!info) fail(`FE3: no secured UpdateInfo for ID ${match.id}`);
const ident = (info.match(/<UpdateIdentity [^>]*>/) || [])[0];
const updateId = ident && attr(ident, 'UpdateID'), revision = ident && attr(ident, 'RevisionNumber');
if (!/^[0-9a-f-]{36}$/i.test(updateId ?? '') || !/^\d+$/.test(revision ?? '')) fail('FE3: bad UpdateIdentity');
log(`FE3: update ${updateId} rev ${revision} file ${match.fileName} size ${match.size}`);
if (match.size && Number(match.size) !== expSize) fail(`FE3 file size ${match.size} != DCAT ${expSize}`);

const urlXml = xmlUnescape(await fe3(`${FE3}/secured`, 'GetExtendedUpdateInfo2', `<GetExtendedUpdateInfo2 xmlns="http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService">
<updateIDs><UpdateIdentity><UpdateID>${updateId}</UpdateID><RevisionNumber>${revision}</RevisionNumber></UpdateIdentity></updateIDs>
<infoTypes><XmlUpdateFragmentType>FileUrl</XmlUpdateFragmentType><XmlUpdateFragmentType>FileDecryption</XmlUpdateFragmentType></infoTypes>
<deviceAttributes>${DEVICE}</deviceAttributes></GetExtendedUpdateInfo2>`));
const locs = blocks(urlXml, 'FileLocation').map(b => ({ digest: (b.match(/<FileDigest>([^<]+)<\/FileDigest>/) || [])[1], url: (b.match(/<Url>([^<]+)<\/Url>/) || [])[1] }));
const loc = locs.filter(l => l.digest && l.digest === match.digest);
if (loc.length !== 1 || !loc[0].url) fail(`FE3: expected one URL for the package digest, found ${loc.length} (of ${locs.length})`);
log(`Download host: ${new URL(loc[0].url).hostname}`);

// ---- 3. Download and check against DCAT ------------------------------------
fs.mkdirSync(outDir, { recursive: true });
const out = path.join(outDir, 'store.msix');
// Every request, the first and each redirect hop, goes through downloadUrl()
// before it is sent. Microsoft serves this file over plain http only (https on
// these hosts presents another name's certificate); integrity comes from the
// DCAT SHA-256 and size below and the Authenticode check in verify. See
// store-msix-url.mjs.
let url = downloadUrl(loc[0].url), res;
for (let hop = 0; ; hop++) {
  if (hop > 5) fail('too many redirects');
  try { res = await request(url, { limit: expSize + 1 }); }
  catch (e) { fail(`download from ${new URL(url).hostname} failed: ${e.code ?? ''} ${e.message.split('\n')[0]}`); }
  if ([301, 302, 303, 307, 308].includes(res.status)) {
    if (!res.headers.location) fail(`download HTTP ${res.status} without Location`);
    url = downloadUrl(res.headers.location, url);
    continue;
  }
  break;
}
if (res.status !== 200) fail(`download HTTP ${res.status}`);
const gotSha = crypto.createHash('sha256').update(res.body).digest('hex');
if (res.body.length !== expSize) fail(`size ${res.body.length} != DCAT ${expSize}`);
if (gotSha !== expShaHex) fail(`sha256 ${gotSha} != DCAT ${expShaHex}`);
fs.writeFileSync(out, res.body);
fs.writeFileSync(path.join(outDir, 'dcat.json'), JSON.stringify({ productId, fullName, version, size: expSize, sha256: expShaHex, updateId, revision }, null, 1));
log(`OK: ${out} matches DCAT (size and SHA-256)`);
console.log(`version=${version}\nsha256=${gotSha}\nsize=${expSize}\nfull_name=${fullName}`);
