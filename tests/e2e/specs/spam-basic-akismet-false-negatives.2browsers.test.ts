/// <reference path="../test-types.ts"/>

import * as _ from 'lodash';
import assert = require('assert');
import server = require('../utils/server');
import utils = require('../utils/utils');
import pagesFor = require('../utils/pages-for');
import settings = require('../utils/settings');
import make = require('../utils/make');
import logAndDie = require('../utils/log-and-die');
import c = require('../test-constants');

declare let browser: any;
declare let browserA: any;
declare let browserB: any;

let everyone;
let owen;
let owensBrowser;
let mallory;
let mallorysBrowser;

let idAddress: IdAddress;
let forumTitle = "Basic Spam Test Forum";

let countersBefore;

describe("spam test, Akismet false negatives = missed spam  TyT63MKWYT37", () => {

  if (!settings.include3rdPartyDependentTests) {
    console.log("Skipping this spec; no 3rd party credentials specified.");
    return;
  }

  it("initialize people", () => {
    everyone = _.assign(browser, pagesFor(browser));
    owen = make.memberOwenOwner();
    owensBrowser = _.assign(browserA, pagesFor(browserA));
    mallory = make.memberMallory();
    mallorysBrowser = _.assign(browserB, pagesFor(browserB));
  });

  it("import a site", () => {
    let site: SiteData = make.forumOwnedByOwen('basicspam', { title: forumTitle });
    site.settings.numFirstPostsToReview = 9;
    site.settings.numFirstPostsToAllow = 9;
    site.members.push(mallory);
    idAddress = server.importSiteData(site);
    countersBefore = server.getTestCounters();
  });

  it("Mallory logs in", () => {
    mallorysBrowser.go(idAddress.origin);
    mallorysBrowser.complex.loginWithPasswordViaTopbar(mallory);
  });


  // ----- Three spam comments slips by the spam filter

  it("Posts a topic with clever spam links, goes unnoticed", () => {
    mallorysBrowser.complex.createAndSaveTopic(
        { title: "Topic title", body: "Spam spam topic body." });
  });

  it("... and two replies", () => {
    mallorysBrowser.complex.replyToOrigPost("Reply one, spam spam.");
    mallorysBrowser.complex.replyToOrigPost("Reply two, spam spam.");
  });


  // ------ Marking missed spam, as spam

  it("Owen goes to the Review admin tab and logs in", () => {
    owensBrowser.adminArea.goToReview(idAddress.origin, { loginAs: owen });
  });

  it("He deletes Mallory's posts", () => {
    owensBrowser.adminArea.review.rejectDeleteTaskIndex(1);
    owensBrowser.adminArea.review.rejectDeleteTaskIndex(2);
    owensBrowser.adminArea.review.rejectDeleteTaskIndex(3);  // now he gets blocked  [TyT029ASL45]
    owensBrowser.adminArea.review.playTimePastUndo();
  });


  // ----- Now Mallory gets blocked

  it("Mallory's page is gone", () => {
    mallorysBrowser.refresh();
    mallorysBrowser.assertNotFoundError();
  });

  it("Mallory wants to post a new topic", () => {
    mallorysBrowser.go('/');
    mallorysBrowser.complex.createAndSaveTopic(
        { title: "This gets blocked", body: "Blocked topic text.", resultInError: true });
  });

  it("... but now he gets blocked: the server thinks he's a spammer", () => {
    mallorysBrowser.serverErrorDialog.waitForTooManyPendingMaybeSpamPostsError();
  });


  // ------ Report misclassifications

  it("The server reports the false negatives to Akismet", () => {
    let countersNow = server.getTestCounters();
    logAndDie.logMessage(
        `numReportedSpamFalseNegatives before: ${countersBefore.numReportedSpamFalseNegatives}, ` +
        `after: ${countersNow.numReportedSpamFalseNegatives}`);
    while (true) {
      if (countersNow.numReportedSpamFalseNegatives - countersBefore.numReportedSpamFalseNegatives >= 3)
        break;
      process.stdout.write(' ' + countersNow.numReportedSpamFalseNegatives);
      owensBrowser.pause(200);
      countersNow = server.getTestCounters();
    }
  });


});

