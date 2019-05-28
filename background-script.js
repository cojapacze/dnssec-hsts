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
/*global browser, chrome*/
'use strict';
let compatBrowser;
// let isFirefox = false;
// let isChrome = false;
if (typeof browser !== 'undefined') {
  console.info('Testing for browser/chrome: browser');
  compatBrowser = browser;
  // isFirefox = true;
} else {
  console.info('Testing for browser/chrome: chrome');
  compatBrowser = chrome;
  // isChrome = true;
}
const pages = {
  error: compatBrowser.runtime.getURL('/pages/error/index.html'),
  vestibule: compatBrowser.runtime.getURL('/pages/vestibule/index.html')
};
const lookupTimeout = 1000;
const downturnFactor = 10;
const hostnameChecks = new Map();
const matchTargetUrl = 'http://*.bit/*';

function sleep(milliseconds) {
  const start = Date.now();
  let lock = true;
  let timeout;
  do {
    if ((Date.now() - start) > milliseconds) {
      timeout = true;
      lock = false;
    }
  } while (lock);
  return timeout;
}

function buildBlockingResponse(url, apiResponse) {
  if (!apiResponse.ok) {
    return {
      redirectUrl: pages.error
    };
  }
  if (apiResponse.hasTLSA) {
    url.protocol = 'https:';
  }
  return {
    redirectUrl: url.toString()
  };
}

const nativePort = compatBrowser.runtime.connectNative('dnssec_hsts');

nativePort.onMessage.addListener(response => {
  const {hostname, ok} = response;
  const cachedHost = hostnameChecks.get(hostname);
  if (!cachedHost) {
    console.warn(
      `Native DNSSEC app, unexpected response for hostname: ${hostname}`);
    return;
  }
  if (!ok) {
    console.error(`Native DNSSEC app error: ${hostname}`, response);
  }
  cachedHost.apiResponse = response;
});

function createApiRequest(targetURL) {
  if (hostnameChecks.has(targetURL.hostname)) {
    hostnameChecks.delete(targetURL.hostname);
  }
  const apiRequest = {
    lookupTimestamp: Date.now()
  };
  hostnameChecks.set(targetURL.hostname, apiRequest);
  const message = {
    host: targetURL.host,
    hostname: targetURL.hostname,
    port: targetURL.port
  };
  nativePort.postMessage(message);
  return apiRequest;
}

function upgradeTargetRequest(requestDetails) {
  const targetURL = new URL(requestDetails.url);
  let apiRequest = hostnameChecks.get(targetURL.hostname);
  if (
    !apiRequest ||
    (apiRequest.lookupTimestamp + lookupTimeout) < Date.now()
  ) {
    apiRequest = createApiRequest(targetURL);
  }
  if (apiRequest && apiRequest.apiResponse) {
    return buildBlockingResponse(targetURL, apiRequest.apiResponse);
  }
  const vestibuleURL = new URL(pages.vestibule);
  vestibuleURL.searchParams.set('url', targetURL.toString());
  return {
    redirectUrl: vestibuleURL.toString()
  };
}

function upgradeVestibuleProgress(requestDetails) {
  const vestibuleURL = new URL(requestDetails.url);
  const targetURL = new URL(vestibuleURL.searchParams.get('url'));
  let apiRequest = hostnameChecks.get(targetURL.hostname);
  if (!apiRequest) {
    apiRequest = createApiRequest(targetURL);
  }
  if (!apiRequest.apiResponse) {
    let retry = (parseInt(vestibuleURL.searchParams.get('retry'), 10) || 0);
    sleep(retry * downturnFactor);
    retry += 1;
    vestibuleURL.searchParams.set('retry', retry);
    return {
      redirectUrl: vestibuleURL.toString()
    };
  }
  return buildBlockingResponse(targetURL, apiRequest.apiResponse);
}

function attachTargetRequestListener() {
  compatBrowser.webRequest.onBeforeRequest.addListener(
    upgradeTargetRequest,
    {urls: [matchTargetUrl]},
    ['blocking']
  );
}
attachTargetRequestListener();

function attachVestibuleRequestListener() {
  compatBrowser.webRequest.onBeforeRequest.addListener(
    upgradeVestibuleProgress,
    {urls: [
      `${pages.vestibule}*`
    ]},
    ['blocking']
  );
}
attachVestibuleRequestListener();
