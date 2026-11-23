// node --test .github/scripts/store-msix-url.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { checkDownloadUrl } from './store-msix-url.mjs';

const fe3 = 'http://tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/abc?P1=1&P2=x';
const sec = 'https://tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/abc?P1=1';

test('accepts the FE3 http URL and https, on allowed hosts and default ports', () => {
  assert.equal(checkDownloadUrl(fe3), fe3);
  assert.equal(checkDownloadUrl(sec), sec);
  assert.equal(checkDownloadUrl('http://tlu.dl.delivery.mp.microsoft.com:80/f'), 'http://tlu.dl.delivery.mp.microsoft.com/f');
  assert.equal(checkDownloadUrl('https://2.tlu.DL.Delivery.mp.microsoft.com:443/x'), 'https://2.tlu.dl.delivery.mp.microsoft.com/x');
  assert.equal(checkDownloadUrl('https://delivery.mp.microsoft.com/x'), 'https://delivery.mp.microsoft.com/x');
});

test('redirects: resolved against the current URL, then the same checks', () => {
  assert.equal(checkDownloadUrl('/other/file', fe3), 'http://tlu.dl.delivery.mp.microsoft.com/other/file');
  assert.equal(checkDownloadUrl('https://7.tlu.dl.delivery.mp.microsoft.com/f', fe3), 'https://7.tlu.dl.delivery.mp.microsoft.com/f');
  assert.equal(checkDownloadUrl('http://8.tlu.dl.delivery.mp.microsoft.com/f', sec), 'http://8.tlu.dl.delivery.mp.microsoft.com/f');
  assert.throws(() => checkDownloadUrl('https://evil.example/x', fe3), /host/);
  assert.throws(() => checkDownloadUrl('//evil.example/x', fe3), /host/);
  assert.throws(() => checkDownloadUrl('http://tlu.dl.delivery.mp.microsoft.com:8080/x', sec), /port/);
});

test('rejects other schemes', () => {
  for (const u of ['ftp://tlu.dl.delivery.mp.microsoft.com/x', 'file:///etc/passwd', 'data:text/plain,x', 'ws://tlu.dl.delivery.mp.microsoft.com/x']) {
    assert.throws(() => checkDownloadUrl(u), /scheme/, u);
  }
});

test('rejects hosts outside delivery.mp.microsoft.com', () => {
  for (const u of [
    'http://evil.example/x',
    'https://delivery.mp.microsoft.com.evil.example/x',
    'http://evildelivery.mp.microsoft.com/x',
    'https://mp.microsoft.com/x',
    'http://tlu.dl.delivery.mp.microsoft.com.%65vil.example/x',
    'http://1.2.3.4/x',
    'https://[::1]/x',
  ]) assert.throws(() => checkDownloadUrl(u), /host|parse/, u);
});

test('rejects non-default ports, crossed ports and userinfo', () => {
  assert.throws(() => checkDownloadUrl('https://tlu.dl.delivery.mp.microsoft.com:8443/x'), /port/);
  assert.throws(() => checkDownloadUrl('http://tlu.dl.delivery.mp.microsoft.com:8080/x'), /port/);
  assert.throws(() => checkDownloadUrl('http://tlu.dl.delivery.mp.microsoft.com:443/x'), /port/);
  assert.throws(() => checkDownloadUrl('https://tlu.dl.delivery.mp.microsoft.com:80/x'), /port/);
  assert.throws(() => checkDownloadUrl('http://u:p@tlu.dl.delivery.mp.microsoft.com/x'), /credentials/);
  assert.throws(() => checkDownloadUrl('https://u@tlu.dl.delivery.mp.microsoft.com/x'), /credentials/);
});

test('rejects garbage', () => {
  assert.throws(() => checkDownloadUrl('not a url'), /parse/);
  assert.throws(() => checkDownloadUrl(''), /parse/);
});
