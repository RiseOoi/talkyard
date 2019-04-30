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
let maria;
let mariasBrowser;
let mallory;
let mallorysBrowser;
let mons;
let monsBrowser;
let guest;
let guestsBrowser;
let strangersBrowser;

let idAddress: IdAddress;
let forumTitle = "Basic Spam Test Forum";
let topicTitle = "Links links links";
let post2Selector = '#post-2';
let post3Selector = '#post-3';

let notSpamPageUrl: string;

const AkismetAlwaysSpamName = 'viagra-test-123';
const AkismetAlwaysSpamEmail = 'akismet-guaranteed-spam@example.com';

const topicOneNotSpamTitle = 'topicOneNotSpamTitle'
const topicOneNotSpamBody = 'topicOneNotSpamBody'
const replyOneNotSpam = 'replyOneNotSpam';

// ' --viagra-test-123--' makes Akismet always claim the post is spam.
const replyTwoIsSpam = 'replyTwoIsSpam --viagra-test-123--';
const topicTwoTitle = 'topicTwoTitle';
const topicTwoIsSpamBody = 'topicTwoIsSpamBody --viagra-test-123--';

const spamReplyThree = "This reply gets blocked. --viagra-test-123--";


describe("spam test, external services like Akismet and Google Safe Browsing  TyTSPEXT", () => {

  if (!settings.include3rdPartyDependentTests) {
    console.log("Skipping this spec; no 3rd party credentials specified.");
    return;
  }

  it("initialize people", () => {
    everyone = _.assign(browser, pagesFor(browser));
    owen = make.memberOwenOwner();
    owensBrowser = _.assign(browserA, pagesFor(browserA));
    mons = make.memberModeratorMons();
    maria = make.memberMaria();
    mallory = make.memberMallory();
    guest = make.guestGunnar();
    // Reuse the same browser.
    monsBrowser = _.assign(browserB, pagesFor(browserB));
    mariasBrowser = monsBrowser;
    mallorysBrowser = monsBrowser;
    guestsBrowser = monsBrowser;
    strangersBrowser = monsBrowser;
  });

  it("import a site", () => {
    let site: SiteData = make.forumOwnedByOwen('basicspam', { title: forumTitle });
    site.settings.numFirstPostsToReview = 9;
    site.settings.numFirstPostsToAllow = 9;
    site.members.push(mons);
    site.members.push(maria);
    idAddress = server.importSiteData(site);
  });

  it("Mallory tries to sign up with a spammers address", () => {
    mallorysBrowser.go(idAddress.origin);
    mallorysBrowser.complex.signUpAsMemberViaTopbar(
        { ...mallory, emailAddress: AkismetAlwaysSpamEmail });
  });

  it("... he's rejected, because of the email address", () => {
    mallorysBrowser.serverErrorDialog.waitForIsRegistrationSpamError();
  });

  it("... closes the dialogs", () => {
    mallorysBrowser.serverErrorDialog.close();
    mallorysBrowser.loginDialog.clickCancel();
  });

  it("Mallory retries with a non-spam address", () => {
    mallorysBrowser.complex.signUpAsMemberViaTopbar(mallory);
    var link = server.getLastVerifyEmailAddressLinkEmailedTo(
        idAddress.id, mallory.emailAddress, mallorysBrowser);
    mallorysBrowser.go(link);
    mallorysBrowser.waitAndClick('#e2eContinue');
    mallorysBrowser.disableRateLimits();
  });

  it("He then submits a topic, not spam, works fine", () => {
    mallorysBrowser.complex.createAndSaveTopic(
        { title: topicOneNotSpamTitle, body: topicOneNotSpamBody });
    notSpamPageUrl = mallorysBrowser.url().value;
  });

  it("... and a not-spam reply", () => {
    mallorysBrowser.complex.replyToOrigPost(replyOneNotSpam); // notSpamPageUrl reply 1
  });

  it("He then submits a spam reply ...", () => {
    mallorysBrowser.complex.replyToOrigPost(replyTwoIsSpam);  // notSpamPageUrl reply 2, and
                                                              // suspect spam post 1/3
  });

  it("... which will be visible, initially", () => {
    mallorysBrowser.waitForVisible(post2Selector);  // reply one
    mallorysBrowser.waitForVisible(post3Selector);  // reply two
    assert(!mallorysBrowser.topic.isPostBodyHidden(c.FirstReplyNr));
    assert(!mallorysBrowser.topic.isPostBodyHidden(c.FirstReplyNr + 1));
  });

  it("The spam reply gets hidden, eventually", () => {
    mallorysBrowser.topic.refreshUntilBodyHidden(c.FirstReplyNr + 1);
    assert(mallorysBrowser.topic.isPostBodyHidden(c.FirstReplyNr + 1));
  });

  it("But not the non-spam reply", () => {
    mallorysBrowser.waitForVisible(post2Selector);  // reply one
    assert(!mallorysBrowser.topic.isPostBodyHidden(c.FirstReplyNr));
  });

  it("Mallory posts a spam topic", () => {
    mallorysBrowser.topbar.clickHome();
    mallorysBrowser.complex.createAndSaveTopic(            // suspect spam 2/3
        { title: topicTwoTitle, body: topicTwoIsSpamBody });
  });

  it("... which initially is visible", () => {
    assert(!mallorysBrowser.topic.isPostBodyHidden(c.BodyNr));
  });

  it("... after a while, the topic is considered spam, and hidden", () => {
    mallorysBrowser.topic.refreshUntilBodyHidden(c.BodyNr);
    assert(mallorysBrowser.topic.isPostBodyHidden(c.BodyNr));
  });


  // ----- Too many seems-like-spam comments, Mallory gets blocked

  it("Mallory posts a fifth post — spam, for the 3rd time", () => {
    mallorysBrowser.go(notSpamPageUrl);
    mallorysBrowser.complex.replyToOrigPost(spamReplyThree); // notSpamPageUrl reply 3, and
                                                   // suspect spam 3/3 — gets Mallory blocked
  });

  it("... which initially is visible", () => {
    assert(!mallorysBrowser.topic.isPostBodyHidden(c.FirstReplyNr + 2));
  });

  it("... but soon get hidden, because is spam", () => {
    mallorysBrowser.topic.refreshUntilBodyHidden(c.FirstReplyNr + 2);
    assert(mallorysBrowser.topic.isPostBodyHidden(c.FirstReplyNr + 2));
  });

  it("Mallory tries to post another reply", () => {
    mallorysBrowser.complex.replyToOrigPost("This reply gets blocked.");
  });

  it("... but gets blocked: max 3 pending maybe-spam posts allowed [TyT029ASL45], " +
      "even though site.settings.numFirstPostsToAllow is 9", () => {
    mallorysBrowser.serverErrorDialog.waitForTooManyPendingMaybeSpamPostsError();
  });

  it("... closes the error dialog", () => {
    mallorysBrowser.serverErrorDialog.close();
    mallorysBrowser.editor.cancelNoHelp();
  });

  it("Mallory wants to post a new topic", () => {
    mallorysBrowser.topbar.clickHome();
    mallorysBrowser.complex.createAndSaveTopic(
        { title: "This gets blocked", body: "Blocked topic text.", resultInError: true });
  });

  it("... but also the new topic gets blocked", () => {
    mallorysBrowser.serverErrorDialog.waitForTooManyPendingMaybeSpamPostsError();
  });


  // ------ Reviewing spam

  it("Owen goes to the Review admin tab and logs in", () => {
    owensBrowser.adminArea.goToReview(idAddress.origin, { loginAs: owen });
  });

  it("He reject-deletes the thre spam posts", () => {
    owensBrowser.adminArea.review.rejectDeleteTaskIndex(1);
    owensBrowser.adminArea.review.rejectDeleteTaskIndex(2);
    owensBrowser.adminArea.review.rejectDeleteTaskIndex(3);
    owensBrowser.adminArea.review.playTimePastUndo();
  });

  it("Mallory is still blocked", () => {
    mallorysBrowser.go(notSpamPageUrl);
    mallorysBrowser.complex.replyToOrigPost("Gets blocked");
  });

  it("... but he's stil blocked", () => {
    mallorysBrowser.serverErrorDialog.waitForTooManyPendingMaybeSpamPostsError();
  });


  // ------ Banning the spammer

  // TESTS_MISSING: Owen clicks some shortcut button and bans Mallory,
  // who gets logged out, and cannot login again.

});

