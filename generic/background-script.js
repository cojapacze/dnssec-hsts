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

let unifiedBrowser;
// let isFirefox;
let isChrome;

// Firefox supports both browser and chrome; Chromium only supports chrome;
// Edge only supports browser.  See https://stackoverflow.com/a/45985333
if (typeof browser !== 'undefined') {
  console.log('Testing for browser/chrome: browser');
  // isFirefox = true;
  unifiedBrowser = browser;
} else {
  console.log('Testing for browser/chrome: chrome');
  isChrome = true;
  unifiedBrowser = chrome;
}

const httpLookupApiUrl = 'http://127.0.0.1:8080/lookup';
const matchHostPattern = 'http://*.bit/*';
const nativeLookupAppName = 'org.namecoin.dnssec_hsts';
const pages = {
  error: unifiedBrowser.runtime.getURL('/pages/lookup_error/index.html')
};
const pendingUpgradeChecks = new Map();
let communicationType = 'native';
let nativePort; // Only used with native messaging


function queryUpgradeNative(requestDetails, resolve) {
  const url = new URL(requestDetails.url);
  const {host, hostname, port} = url;
  if (!pendingUpgradeChecks.has(host)) {
    pendingUpgradeChecks.set(host, new Set());

    const message = {host, hostname, port};

    // Send message to the native DNSSEC app
    nativePort.postMessage(message);
  }
  pendingUpgradeChecks.get(host).add({
    url: url,
    callback: resolve
  });
}

// Adapted from Tagide/chrome-bit-domain-extension
// Returns true if timed out, returns false if hostname showed up
function sleep(milliseconds, queryFinishedRef) {
  // synchronous XMLHttpRequests from Chrome extensions are not blocking event
  // handlers. That's why we use this pretty little sleep function to try to get
  // the API response before the request times out.
  const start = Date.now();
  let lock = true;
  let timeout;
  do {
    if ((Date.now() - start) > milliseconds) {
      timeout = true;
      lock = false;
    }
    if (queryFinishedRef.val) {
      timeout = false;
      lock = false;
    }
  } while (lock);
  return timeout;
}

function buildBlockingResponse(url, upgrade, lookupError) {
  if (lookupError) {
    return {redirectUrl: pages.error};
  }
  if (upgrade) {
    if (!isChrome) {
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
  const {host, hostname} = url;

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
        console.error(`Error received from API: status ${xhr.status}`);
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
    console.error(`Error reaching API: ${e.toString()}`);
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
  if (result.trim()) {
    console.info(`Upgraded via TLSA: ${host}`);
    upgrade = true;
  }

  return buildBlockingResponse(url, upgrade, lookupError);
}

// upgradeAsync function returns a Promise
// which is resolved with the upgrade after the native DNSSEC app replies
function upgradeAsyncNative(requestDetails) {
  return new Promise((resolve, reject) => {
    queryUpgradeNative(requestDetails, resolve, reject);
  });
}

function upgradeUnified(requestDetails, chromiumAsyncResolve) {
  switch (communicationType) {
    case 'native':
      if (isChrome) {
        if (typeof chromiumAsyncResolve === 'function') {
          upgradeAsyncNative(requestDetails).then(chromiumAsyncResolve);
          return false;
        }
        // chromiumAsyncResolve not found, fallback to sync HTTP
        return upgradeSyncOverHttp(requestDetails);
      }
      return upgradeAsyncNative(requestDetails);
    default:
      return upgradeSyncOverHttp(requestDetails);
  }
}

function connectNative() {
  /*
  On startup, connect to the Namecoin "dnssec_hsts" app.
  */
  nativePort = unifiedBrowser.runtime.connectNative(nativeLookupAppName);

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

    for (const query of pendingUpgradeChecks.get(host)) {
      query.callback(buildBlockingResponse(query.url, hasTLSA, !ok));
    }
    pendingUpgradeChecks.delete(host);
  });
}

function getExtraInfoSpecOptional() {
  const extraInfoSpecOptional = ['blocking'];
  if (isChrome && communicationType === 'native') {
    extraInfoSpecOptional[0] = 'asyncBlocking';
    let validated = false;
    extraInfoSpecOptional.__defineGetter__(0, () => {
      if (!validated) {
        validated = true;
        return 'blocking';
      }
      return 'asyncBlocking';
    });
  }
  return extraInfoSpecOptional;
}

function attachRequestListener() {
  unifiedBrowser.webRequest.onBeforeRequest.addListener(
    upgradeUnified,
    {urls: [matchHostPattern]},
    getExtraInfoSpecOptional()
  );
}

try {
  if (communicationType === 'native') {
    connectNative();
  }
  attachRequestListener();
} catch (e) {
  console.warn(
    'Exception while attaching listener, fallback to sync HTTP lookup', e);
  communicationType = 'sync_over_http';
  attachRequestListener();
}
