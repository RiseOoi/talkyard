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

const AkismetAlwaysSpamName = 'viagra-test-123';
const AkismetAlwaysSpamEmail = 'akismet-guaranteed-spam@example.com';

const topicOneNotSpamTitle = 'topicOneNotSpamTitle'
const topicOneNotSpamBody = 'topicOneNotSpamBody'
const replyOneNotSpam = 'replyOneNotSpam';

// ' --viagra-test-123--' makes Akismet always claim the post is spam.
const replyTwoIsSpam = 'replyTwoIsSpam --viagra-test-123--';
const topicTwoTitle = 'topicTwoTitle';
const topicTwoIsSpamBody = 'topicTwoIsSpamBody --viagra-test-123--';


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
    site.settings.numFirstPostsToReview = 2;
    site.settings.numFirstPostsToAllow = 4;
    site.members.push(mons);
    site.members.push(maria);
    //site.members.push(mallory);
    idAddress = server.importSiteData(site);
  });

  it("Mallory tries to sign up with a spammers address", () => {
    mallorysBrowser.go(idAddress.origin);
    mallorysBrowser.complex.signUpAsMemberViaTopbar(
        { ...mallory, emailAddress: AkismetAlwaysSpamEmail });
  });

  it("... he's rejected, because of the email address", () => {
    mallorysBrowser.serverErrorDialog.waitForIsSpamError();
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
  });

  it("... and a not-spam reply", () => {
    mallorysBrowser.complex.replyToOrigPost(replyOneNotSpam);
  });

  it("He then submits a spam reply ...", () => {
    mallorysBrowser.complex.replyToOrigPost(replyTwoIsSpam);
  });

  it("... which will be visible, initially", () => {
    mallorysBrowser.waitForVisible(post2Selector);  // reply one
    mallorysBrowser.waitForVisible(post3Selector);  // reply two
  });

  it("The spam reply gets hidden, eventually", () => {
    mallorysBrowser.topic.refreshUntilBodyHidden(c.FirstReplyNr + 1);
  });

  it("But not the non-spam reply", () => {
    mallorysBrowser.waitForVisible(post2Selector);  // reply one
  });

  it("Mallory posts a spam topic", () => {
    mallorysBrowser.topbar.clickHome();
    mallorysBrowser.complex.createAndSaveTopic(
        { title: topicTwoTitle, body: topicTwoIsSpamBody });
  });

  it("... which initially is visible", () => {
    assert(!mallorysBrowser.topic.isPostBodyHidden(c.BodyNr));
  });

  it("... after a while, the topic is considered spam, and hidden", () => {
    mallorysBrowser.topic.refreshUntilBodyHidden(c.BodyNr);
    assert(mallorysBrowser.topic.isPostBodyHidden(c.BodyNr));
  });

  it("Mallory tries to posts a fifth post (a new topic)", () => {
    mallorysBrowser.topbar.clickHome();
    mallorysBrowser.complex.createAndSaveTopic(
        { title: topicTwoTitle, body: topicTwoIsSpamBody, resultInError: true });
  });

  it("... however, ... allow = 4, this was nr 5", () => {
    mallorysBrowser.debug();
  });


  // ------ Reviewing spam

  it("Owen goes to the Review admin tab and logs in", () => {
    owensBrowser.adminArea.goToReview(idAddress.origin);
    owensBrowser.loginDialog.loginWithPassword(owen);
  });


  // ------ Banning the spammer

});

