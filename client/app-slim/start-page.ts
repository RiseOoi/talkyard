/*
 * Copyright (c) 2010-2018 Kaj Magnus Lindberg
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/// <reference path="prelude.ts" />
/// <reference path="init-all-react-roots.ts" />

const d = { i: debiki.internal };

const scriptLoadDoneCallbacks = [];
debiki.scriptLoad = {  // RENAME to tyd.whenStarted(...) ?
  done: function(callback) {
    scriptLoadDoneCallbacks.push(callback);
  }
};


let resolveServiceWorkerPromise;
let rejectServiceWorkerPromise;

// move to tyd
debiki.serviceWorkerPromise = new Promise<ServiceWorker>(function (resolve, reject) {
  resolveServiceWorkerPromise = resolve;
  rejectServiceWorkerPromise = reject;
});

let serviceWorkerIsSameVersion = false;

debiki.nowServiceWorkerIsRightVersion = function() {
  serviceWorkerIsSameVersion = true;
};


const allPostsNotTitleSelector = '.debiki .dw-p:not(.dw-p-ttl)';


function handleLoginInOtherBrowserTab() {
  const currentUser = debiki2.ReactStore.getMe();
  const sessionId = getSetCookie('dwCoSid');
  if (currentUser.isLoggedIn) {
    if (sessionId) {
      // Session id example: (parts: hash, user id, name, login time, random value)
      // 'Y1pBlH7vY4JW9A.11.Magnus.1316266102779.15gl0p4xf7'
      const parts = sessionId.split('.');
      const newUserIdString = parts[1];
      if (currentUser.userId !== parseInt(newUserIdString)) {
        // We've logged in as another user in another browser tab.
        debiki2.ReactActions.loadMyself();
      }
    }
    else {
      const mainWin = debiki2.getMainWin();
      if (mainWin.typs.currentPageSessionId) {
        // We're logged in, cookieless. Fine. [NOCOOKIES]
      }
      else {
        // We've logged out in another browser tab. The server should already know about this.
        debiki2.ReactActions.logoutClientSideOnly();
      }
    }
  }
  else if (sessionId) {
    // We've logged in in another browser tab.
    debiki2.ReactActions.loadMyself();
  }
}


function registerEventHandlersFireLoginOut() {
  // If the user switches browser tab, s/he might logout and login
  // in another tab. That'd invalidate all xsrf tokens on this page,
  // and user specific permissions and ratings info (for this tab).
  // Therefore, when the user switches back to this tab, check
  // if a new session has been started.
  Bliss.events(window, { 'focus': handleLoginInOtherBrowserTab });
}


/**
 * If the URL query string contains 2d=true/false, enables/disables
 * horizontal comments. If the screen is narrow, forces one-column-layout.
 * Returns the layout type in use: 'OneColumnLayout' or 'TreeLayout'.
 */
function chooseInitialLayout() {
  const queryString = window.location.search;
  const shallEnable2d = queryString.search('2d=true') !== -1;
  const shallDisable2d = queryString.search('2d=false') !== -1 ||
      // use window.outerWidth — it doesn't force a layout reflow (and it's fine that it might
      // be a bit inexact because of browser window borders).
      Math.max(window.outerWidth, window.outerHeight) < 1000;
  const store: Store = debiki2.ReactStore.allData();
  const page: Page = store.currentPage;
  const is2dEnabled = page.horizontalLayout;
  if (is2dEnabled && shallDisable2d) {
    disableHzComments();
    return 'OneColumnLayout';
  }
  if (!is2dEnabled && shallEnable2d) {
    enableHzComments();
    return 'TreeLayout';
  }

  const htmlElemClasses = document.documentElement.classList;

  function disableHzComments(){
    htmlElemClasses.remove('dw-hz');
    htmlElemClasses.add('dw-vt');
    _.each(debiki2.$$all('.dw-depth-0'), function(threadElem) {
      debiki2.$h.removeClasses(threadElem, 'dw-hz');
    });
    debiki2.ReactActions.setHorizontalLayout(false);
  }

  function enableHzComments(){
    htmlElemClasses.remove('dw-vt');
    htmlElemClasses.add('dw-hz');
    _.each(debiki2.$$all('.dw-depth-0'), function(threadElem) {
      debiki2.$h.addClasses(threadElem, 'dw-hz');
    });
    debiki2.ReactActions.setHorizontalLayout(true);
  }

  if (is2dEnabled) {
    return 'TreeLayout';
  }
  else {
    return 'OneColumnLayout';
  }
}


// REFACTOR rename this file to render-page-in-browser.ts? [7VUBWR45]

/**
 * Renders the page, step by step, to reduce page loading time. (When the
 * first step is done, the user should conceive the page as mostly loaded.)
 */
function renderPageInBrowser() {
  debiki2.ReactStore.initialize();
  const _2dLayout = chooseInitialLayout() === 'TreeLayout';
  if (_2dLayout) {
    debiki2.utils.onMouseDetected(debiki2.Server.load2dScriptsBundleStart2dStuff);
  }

  // Later, when having tested for a bit, use 'hydrate' by default.
  // ReactDOM.hydrate() reuses server generated html, whereas render() ignores it, rerenders everything.
  let reactRenderMethod: 'render' | 'hydrate' = 'render';

  // @ifdef DEBUG
  reactRenderMethod = 'hydrate';
  let isServerHtmlStale = false;
  let htmlBefore;
  let htmlAfter;
  // @endif

  console.log("Cached html version: <" + eds.cachedVersion +
      ">, current: <" + eds.currentVersion + "> [TyMPAGEVER]");

  const store: Store = debiki2.ReactStore.allData();
  if (store.currentPage && store.currentPage.pageRole === PageRole.Forum) {
    // Maybe there's a topic list offset, or non-default different sort order, so we cannot
    // reuse the html from the server. [7TMW4ZJ5]
    reactRenderMethod = 'render';
  }
  else if (location.pathname.search('/-/') === 0) {
    // This isn't rendered server side, so there's no html to reuse.
    reactRenderMethod = 'render';
  }
  else if (eds.currentVersion.split('|')[1] !== eds.cachedVersion.split('|')[1]) {
    // @ifdef DEBUG
    isServerHtmlStale = true;
    htmlBefore = document.getElementById('dwPosts').innerHTML;
    // @endif
    console.log("Cached React store json and html is stale. I will rerender. [TyMRERENDER]");
    reactRenderMethod = 'render';
  }

  if (location.search.indexOf('&hydrate=false') >= 0) {
    console.log("Will use ReactDOM.render, because '&hydrate=false'. [TyMFORCRNDR]");
    reactRenderMethod = 'render';
  }

  if (location.search.indexOf('&hydrate=true') >= 0) {
    console.log("Will use ReactDOM.hydrate, because '&hydrate=true'. [TyMFORCHYDR]");
    reactRenderMethod = 'hydrate';
  }

  const timeBefore = performance.now();

  debiki2.startMainReactRoot(reactRenderMethod);

  const timeAfterPageContent = performance.now();

  // @ifdef DEBUG
  if (isServerHtmlStale) {
    htmlAfter = document.getElementById('dwPosts').innerHTML;
    (<any> window).isServerHtmlStale = true;
    (<any> window).htmlFromServer = htmlBefore;
    (<any> window).htmlAfterReact = htmlAfter;
    console.warn("*** React store checksum mismatch. *** Compare window.htmlFromServer " +
        "with htmlAfterReact to find out what the problem (if any) maybe is.")
  }
  // @endif

  const posts = debiki2.$bySelector(allPostsNotTitleSelector);
  const numPosts = posts.length;
  const timeBeforeTimeAgo = performance.now();
  // Only process the header right now if there are many posts.
  debiki2.processTimeAgo(numPosts > 20 ? '.dw-ar-p-hd' : '');
  const timeAfterTimeAgo = performance.now();

  debiki2.ReactStore.activateVolatileData();
  const timeAfterUserData = performance.now();

  // Skip sidebars, when (rendering as if we were) inside an iframe — they'd become sidebars
  // inside the iframe, which would look weird, + the watchbar doesn't make sense;
  // it'd try to navigate inside the iframe.
  let timeAfterRemainingRoots = NaN;
  if (!store.isEmbedded) {
    debiki2.createSidebar();
    debiki2.watchbar.createWatchbar();
    timeAfterRemainingRoots = performance.now();
  }

  console.log(`Millis to ReactDOM.${reactRenderMethod} page: ${timeAfterPageContent - timeBefore}` +
    ", time-ago: " + (timeAfterTimeAgo - timeBeforeTimeAgo) +
    ", user data: " + (timeAfterUserData - timeAfterTimeAgo) +
    ", remaining roots: " + (timeAfterRemainingRoots - timeAfterUserData) + " [TyMRNDRPERF]");

  document.documentElement.classList.add(ReactStartedClass);

  debiki2.page.activateLikeButtons(debiki2.ReactStore.allData().settings);

  setTimeout(runNextStep, 60);


  const steps = [];

  steps.push(function() {
    registerEventHandlersFireLoginOut();
    registerServiceWorkerWaitForSameVersion();

    debiki2.utils.startDetectingMouse();
    debiki2.ReactActions.doUrlFragmentAction();

    // Smooth sroll and take topbar into account, when clicking a #local-anchor:
    // However, preventDefault() also stops the url hash frag from updating at all :-/
    /* So skip this:
    Bliss.delegate(document.body, 'click', 'a', function(event){
      const hrefInclHost: string | undefined = event.target.href;
      if (!hrefInclHost) return;
      const anyLocalHash = hrefInclHost.replace(
        location.origin + location.pathname + (localStorage.query || '') + '#', '#');
      if (anyLocalHash[0] === '#') {
        event.preventDefault();
      }
    }); */
    window.addEventListener('hashchange', function(eventIgnored) {
      debiki2.ReactActions.doUrlFragmentAction();
    });
  });

  steps.push(function() {
    debiki2.form.activateAnyCustomForm();
    debiki2.page.Hacks.reactRouterLinkifyTopHeaderLinks();
  });

  // Disable for now, I'll rewrite it to consider timestamps.
  //steps.push(d.i.startNextUnreadPostCycler);

  /* Post pins disabled right now, after I ported to React.
  steps.push(function() {
    d.i.makePinsDragsortable();
  }); */

  steps.push(function() {
    // Process any remaining time-ago:s, in case we didn't do all at once earlier.
    // Plus add collapse-thread buttons, for tall threads.
    debiki2.page.Hacks.processPosts();
    debiki2.page.PostsReadTracker.start();

    debiki.serviceWorkerPromise.then(function(sw) {
      // The service worker is of the same version as this page js code,
      // we checked that here [SWSAMEVER].
      sw.postMessage(<StartMagicTimeSwMessage> {
        doWhat: SwDo.StartMagicTime,
        startTimeMs: eds.testNowMs,
      });
    }).finally(lastStep);
  });

  function lastStep() {
    debiki2.startMagicTime(eds.testNowMs);
    _.each(scriptLoadDoneCallbacks, function(c) { c(); });
    console.log("Page started. [TyMPGSTRTD]");
  }

  function runNextStep() {
    steps[0]();
    steps.shift();
    if (steps.length > 0)
      setTimeout(runNextStep, 50);
  }
}


function registerServiceWorkerWaitForSameVersion() {  // [REGSW]
  if (!eds.useServiceWorker) {
    if (eds.wantsServiceWorker) {
      console.warn("Cannot use any service worker — they require HTTPS or http://localhost, " +
          "not incognito mode. [TyMSWMISSNG]");
    }
    else {
      console.log("Not using any service worker. [TyMSWSKIPD]");
    }
    rejectServiceWorkerPromise();
    return;
  }

  var dotMin = '.min';
  // @ifdef DEBUG
  dotMin = '';
  // @endif

  navigator.serviceWorker.addEventListener('controllerchange', (controllerchangeevent) => {
    console.log("Service worker controllerchange event [TyMSWCTRCHG]");
  });

  navigator.serviceWorker.register(`/talkyard-service-worker${dotMin}.js`)
      .then(function(registration) {
        console.log("Service worker registered. [TyMSWREGOK]");
        registration.onupdatefound = function() {
          console.log("New service worker available [TyMNWSWAVL]");
        };

        // Optionally, check for new app versions, each hour. This'll download
        // any new service worker, and (not impl?) here in the page js we'll notice
        // the service worker starts including a newer version number in its
        // messages to us — then we can ask the user to reload the page. [NEWSWVER]
        //
        //setInterval(registration.update, 3600*1000);

        // Wait until a service worker of the same version as this code, is
        // active. Then, resolve the service worker promise:

        let i = 0;
        const intervalHandle = setInterval(function() {
          // This is null until a service worker — possibly an old version we don't want
          // to use — has been installed and activated and handles this browser tab.
          const theServiceWorker = navigator.serviceWorker.controller;
          if (!theServiceWorker)
            return;

          i += 1;

          // There's *some* service worker for this browser tab, but is it the wrong version?
          // When the page loads, that'll happen using the currently installed service
          // worker, possibly an old version, could be a year old, if the user hasn't
          // visited this site in a year.
          // It's *error prone* to write code that works with arbitrarily old service workers?
          // So if it's of a different (older) version, wait until the new one we
          // started installing above, has claimed [SWCLMTBS] this browser tab. Let's
          // poll-ask the service worker about its version, until it's the same version.
          // (Or if newer version — should tell user to refresh page [NEWSWVER]. Not impl.)
          if (i === 1)
            console.log("Service worker active — but which version? [TyMSWACTV]");

          if ((i % 20) === 4)
            console.log("Waiting for service worker to maybe update ... [TyMWAITSWUPD]");

          // Poll the service worker's version: it replies to this message, with
          // its version number.
          theServiceWorker.postMessage(<TellMeYourVersionSwMessage> {
            doWhat: SwDo.TellMeYourVersion,
          });

          // This variable gets updated when the service worker replies to the messages
          // we send just above. (Could use a MessageChannel instead? But this works fine.)
          if (serviceWorkerIsSameVersion) {  // [SWSAMEVER]
            console.log(`Service worker is same version: ${SwPageJsVersion}, fine [TyMEQSWVER]`);
            clearInterval(intervalHandle);
            resolveServiceWorkerPromise(theServiceWorker);
          }
        }, 50)
      }).catch(function(error) {
        console.warn(`Error registering service worker: ${error} [TyESWREGKO]`);
        rejectServiceWorkerPromise();
      });
}


d.i.renderPageInBrowser = function() {
  Bliss.ready().then(renderPageInBrowser);
};


// vim: fdm=marker et ts=2 sw=2 fo=tcqwn list
