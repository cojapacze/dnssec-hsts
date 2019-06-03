/*
Copyright 2017-2019 Jeremy Rand.

This file is part of DNSSEC-HSTS.

DNSSEC-HSTS is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

DNSSEC-HSTS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with DNSSEC-HSTS.  If not, see <https://www.gnu.org/licenses/>.
*/
/* global chrome, browser */
'use strict';
// Based on https://stackoverflow.com/a/45985333
function onFirefox() {
  if (typeof chrome !== 'undefined' && typeof browser !== 'undefined') {
    return true;
  }
  return false;
}

let compatBrowser;
// Firefox supports both browser and chrome; Chromium only supports chrome;
// Edge only supports browser.  See https://stackoverflow.com/a/45985333
if (typeof browser !== 'undefined') {
  console.log('Testing for browser/chrome: browser');
  compatBrowser = browser;
} else {
  console.log('Testing for browser/chrome: chrome');
  compatBrowser = chrome;
}

const pages = {
  error: compatBrowser.runtime.getURL('/pages/lookup_error/index.html')
};
const httpLookupApiUrl = 'http://127.0.0.1:8080/lookup';
const nativeLookupAppName = 'org.namecoin.dnssec_hsts';

// Only used with native messaging
let nativePort;
const pendingUpgradeChecks = new Map();

// host for match pattern for the URLs to upgrade
const matchHost = '*.bit';
let communicationType;
if (onFirefox()) {
  communicationType = 'native';
} else {
  communicationType = 'sync_over_http';
}

function queryUpgradeNative(requestDetails, resolve) {
  const url = new URL(requestDetails.url);
  const host = url.host;
  const hostname = url.hostname;
  const port = url.port;
  if (!pendingUpgradeChecks.has(host)) {
    pendingUpgradeChecks.set(host, new Set());

    const message = {host: host, hostname: hostname, port: port};

    // Send message to the native DNSSEC app
    nativePort.postMessage(message);
  }
  pendingUpgradeChecks.get(host).add(resolve);
}

// upgradeAsync function returns a Promise
// which is resolved with the upgrade after the native DNSSEC app replies
function upgradeAsyncNative(requestDetails) {
  return new Promise((resolve, reject) => {
    queryUpgradeNative(requestDetails, resolve, reject);
  });
}

// Adapted from Tagide/chrome-bit-domain-extension
// Returns true if timed out, returns false if hostname showed up
function sleep(milliseconds, queryFinishedRef) {
  // synchronous XMLHttpRequests from Chrome extensions are not blocking event
  // handlers. That's why we use this
  // pretty little sleep function to try to get the API response before the
  // request times out.
  const start = new Date().getTime();
  for (let i = 0; i < 1e7; i++) {
    if ((new Date().getTime() - start) > milliseconds) {
      return true;
    }
    if (queryFinishedRef.val) {
      return false;
    }
  }
  return true;
}

function buildBlockingResponse(url, upgrade, lookupError) {
  if (lookupError) {
    return {redirectUrl: pages.error};
  }
  if (upgrade) {
    if (onFirefox()) {
      return {upgradeToSecure: true};
    }
    url.protocol = 'https:';
    // Chromium and Edge don't support "upgradeToSecure",
    // so we use "redirectUrl" instead
    return {redirectUrl: url.toString()};
  }
  return {};
}

// Compatibility for Chromium/Edge, which don't support async onBeforeRequest
// See Chromium Bug 904365
function upgradeSyncOverHttp(requestDetails) {
  const url = new URL(requestDetails.url);
  const host = url.host;
  const hostname = url.hostname;
  // const port = url.port;

  let certResponse;
  const queryFinishedRef = {val: false};

  let upgrade = false;
  let lookupError = false;

  // Adapted from Tagide/chrome-bit-domain-extension
  // Get the TLSA records from the API
  const xhr = new XMLHttpRequest();
  const apiUrl = `${httpLookupApiUrl}?domain=${encodeURIComponent(hostname)}`;
  // synchronous XMLHttpRequest is actually asynchronous
  // check out https://developer.chrome.com/extensions/webRequest
  xhr.open('GET', apiUrl, false);
  xhr.onreadystatechange = function () {
    if (xhr.readyState === 4) {
      if (xhr.status !== 200) {
        console.log(`Error received from API: status ${xhr.status}`);
        lookupError = true;
      }

      // Get the certs returned from the API server.
      certResponse = xhr.responseText;
      // Notify the sleep function that we're ready to proceed
      queryFinishedRef.val = true;
    }
  };
  try {
    xhr.send();
  } catch (e) {
    console.log(`Error reaching API: ${e.toString()}`);
    lookupError = true;
  }
  // block the request until the API response is received. Block for up to two
  // seconds.
  if (sleep(2000, queryFinishedRef)) {
    console.log('API timed out');
    lookupError = true;
  }

  // Check if any certs exist in the result
  const result = certResponse;
  if (result.trim() !== '') {
    console.log(`Upgraded via TLSA: ${host}`);
    upgrade = true;
  }

  return buildBlockingResponse(url, upgrade, lookupError);
}

function upgradeCompat(requestDetails) {
  switch (communicationType) {
    case 'native':
      return upgradeAsyncNative(requestDetails);
    default:
      return upgradeSyncOverHttp(requestDetails);
  }
}

// Builds a match pattern for all HTTP URL's for the specified host
function buildPattern(host) {
  return `http://${host}/*`;
}

// Only use this on initial extension startup; afterwards you should use
// resetRequestListener instead.
function attachRequestListener() {
  // add the listener,
  // passing the filter argument and "blocking"
  compatBrowser.webRequest.onBeforeRequest.addListener(
    upgradeCompat,
    {urls: [buildPattern(matchHost)]},
    ['blocking']
  );
}

console.log(`Testing for Firefox: ${onFirefox()}`);

// Firefox is the only browser that supports async onBeforeRequest, and
// therefore is the only browser that we can use native messaging with.
if (communicationType === 'native') {
  /*
  On startup, connect to the Namecoin "dnssec_hsts" app.
  */
  nativePort = compatBrowser.runtime.connectNative(nativeLookupAppName);

  /*
  Listen for messages from the native DNSSEC app.
  */
  nativePort.onMessage.addListener(response => {
    const {host, hasTLSA, ok} = response;

    if (!ok) {
      console.log(`Native DNSSEC app error: ${host}`);
    }

    if (!pendingUpgradeChecks.has(host)) {
      return;
    }

    for (const callback of pendingUpgradeChecks.get(host)) {
      callback(buildBlockingResponse(null, hasTLSA, !ok));
    }

    pendingUpgradeChecks.delete(host);
  });
}

attachRequestListener();
