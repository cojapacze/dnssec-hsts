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

// Only used with native messaging
let nativePort;
const pendingUpgradeChecks = new Map();

// host for match pattern for the URLs to upgrade
const matchHost = '*.bit';
let currentRequestListener;

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
function upgradeAsync(requestDetails) {
  const asyncCancel = new Promise((resolve, reject) => {
    queryUpgradeNative(requestDetails, resolve, reject);
  });

  return asyncCancel;
}

function buildBlockingResponse(url, upgrade, lookupError) {
  if (lookupError) {
    return {redirectUrl:
        compatBrowser.runtime.getURL('/pages/lookup_error/index.html')};
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
function upgradeSync(requestDetails) {
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
  const apiUrl =
      `http://127.0.0.1:8080/lookup?domain=${encodeURIComponent(hostname)}`;
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

  // Check if any certs exist in the result
  const result = certResponse;
  if (result.trim() !== '') {
    console.log(`Upgraded via TLSA: ${host}`);
    upgrade = true;
  }

  return buildBlockingResponse(url, upgrade, lookupError);
}

function upgradeCompat(requestDetails) {
  if (onFirefox()) {
    return upgradeAsync(requestDetails);
  }
  return upgradeSync(requestDetails);
}

// Builds a match pattern for all HTTP URL's for the specified host
function buildPattern(host) {
  return `http://${host}/*`;
}

// Only use this on initial extension startup; afterwards you should use
// resetRequestListener instead.
function attachRequestListener() {
  // This shim function is a hack so that we can add a new listener before we
  // remove the old one.  In theory JavaScript's single-threaded nature makes
  // that irrelevant, but I don't trust browsers to behave sanely on this.
  currentRequestListener = function (requestDetails) {
    return upgradeCompat(requestDetails);
  };

  // add the listener,
  // passing the filter argument and "blocking"
  compatBrowser.webRequest.onBeforeRequest.addListener(
    currentRequestListener,
    {urls: [buildPattern(matchHost)]},
    ['blocking']
  );
}

console.log(`Testing for Firefox: ${onFirefox()}`);

// Firefox is the only browser that supports async onBeforeRequest, and
// therefore is the only browser that we can use native messaging with.
if (onFirefox()) {
  /*
  On startup, connect to the Namecoin "dnssec_hsts" app.
  */
  nativePort = compatBrowser.runtime.connectNative('org.namecoin.dnssec_hsts');

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

    for (const item of pendingUpgradeChecks.get(host)) {
      item(buildBlockingResponse(null, hasTLSA, !ok));
    }

    pendingUpgradeChecks.delete(host);
  });
}

attachRequestListener();
