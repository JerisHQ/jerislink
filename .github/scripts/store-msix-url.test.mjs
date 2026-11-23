// node --test .github/scripts/store-msix-url.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { checkDownloadUrl, fe3DownloadUrl } from './store-msix-url.mjs';

const base = 'https://tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/abc?P1=1';

test('accepts https on delivery.mp.microsoft.com hosts, default port', () => {
  assert.equal(checkDownloadUrl(base), base);
  assert.equal(checkDownloadUrl('https://delivery.mp.microsoft.com/x'), 'https://delivery.mp.microsoft.com/x');
  assert.equal(checkDownloadUrl('https://2.tlu.DL.Delivery.mp.microsoft.com:443/x'), 'https://2.tlu.dl.delivery.mp.microsoft.com/x');
});

test('resolves relative redirects against the current URL', () => {
  assert.equal(checkDownloadUrl('/other/file', base), 'https://tlu.dl.delivery.mp.microsoft.com/other/file');
});

test('rejects other schemes', () => {
  for (const u of ['http://tlu.dl.delivery.mp.microsoft.com/x', 'ftp://tlu.dl.delivery.mp.microsoft.com/x', 'file:///etc/passwd']) {
    assert.throws(() => checkDownloadUrl(u), /scheme/, u);
  }
  assert.throws(() => checkDownloadUrl('//evil.example/x', 'http://tlu.dl.delivery.mp.microsoft.com/'), /scheme/);
});

test('rejects hosts outside delivery.mp.microsoft.com', () => {
  for (const u of [
    'https://evil.example/x',
    'https://delivery.mp.microsoft.com.evil.example/x',
    'https://evildelivery.mp.microsoft.com/x',
    'https://mp.microsoft.com/x',
    'https://tlu.dl.delivery.mp.microsoft.com.%65vil.example/x',
    'https://1.2.3.4/x',
    'https://[::1]/x',
  ]) assert.throws(() => checkDownloadUrl(u), /host|parse/, u);
  assert.throws(() => checkDownloadUrl('https://evil.example/x', base), /host/);
});

test('rejects non-default ports and userinfo', () => {
  assert.throws(() => checkDownloadUrl('https://tlu.dl.delivery.mp.microsoft.com:8443/x'), /port/);
  assert.throws(() => checkDownloadUrl('https://tlu.dl.delivery.mp.microsoft.com:80/x'), /port/);
  assert.throws(() => checkDownloadUrl('https://u:p@tlu.dl.delivery.mp.microsoft.com/x'), /credentials/);
});

test('rejects garbage', () => {
  assert.throws(() => checkDownloadUrl('not a url'), /parse/);
  assert.throws(() => checkDownloadUrl(''), /parse/);
});

test('FE3 URL: http on the allowed host is moved to https, nothing else is', () => {
  assert.equal(fe3DownloadUrl('http://tlu.dl.delivery.mp.microsoft.com/f/a?P1=1&P2=x'), 'https://tlu.dl.delivery.mp.microsoft.com/f/a?P1=1&P2=x');
  assert.equal(fe3DownloadUrl('http://tlu.dl.delivery.mp.microsoft.com:80/f'), 'https://tlu.dl.delivery.mp.microsoft.com/f');
  assert.equal(fe3DownloadUrl(base), base);
  assert.throws(() => fe3DownloadUrl('http://tlu.dl.delivery.mp.microsoft.com:8080/f'), /scheme/);
  assert.throws(() => fe3DownloadUrl('https://tlu.dl.delivery.mp.microsoft.com:8443/f'), /port/);
  assert.throws(() => fe3DownloadUrl('http://evil.example/f'), /host/);
  assert.throws(() => fe3DownloadUrl('http://u:p@tlu.dl.delivery.mp.microsoft.com/f'), /credentials/);
  assert.throws(() => fe3DownloadUrl('ftp://tlu.dl.delivery.mp.microsoft.com/f'), /scheme/);
  assert.throws(() => fe3DownloadUrl('/relative'), /parse/);
});
