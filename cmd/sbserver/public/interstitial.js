// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Controls whether the warning can be overridden.
var overridable_ = true;

// Controls whether there should be a primary button.
var primary_button_ = true;

var expandedDetails = false;
var keyPressState = 0;

// Basic commands that an embedder should handle.
var CMD_DONT_PROCEED = 0;
var CMD_PROCEED = 1;
// Ways for user to get more information.
var CMD_SHOW_MORE_SECTION = 2;
var CMD_OPEN_HELP_CENTER = 3;
var CMD_OPEN_DIAGNOSTIC = 4;


/**
 * A convenience method for sending commands to the parent page.
 * @param {string} cmd  The command to send.
 */
function sendCommand(cmd) {
  // TODO(noelutz): Needs to be defined by the embedder.
  // console.log('Sent command: ' + cmd);
}

/**
 * Alias for document.getElementById. Found elements must be HTMLElements.
 * @param {string} id The ID of the element to find.
 * @return {HTMLElement} The found element or null if not found.
 */
function $(id) {
  var el = document.getElementById(id);
  return el;
}

function toggleDebuggingInfo() {
  $('error-debugging-info').classList.toggle('hidden');
}

function setupEvents() {
  $('body').classList.add('safe-browsing');

  if (!primary_button_) {
    $('primary-button').classList.add('hidden');
  } else {
    $('primary-button').addEventListener('click', function() {
      sendCommand(CMD_DONT_PROCEED);
    });
  }

  if (overridable_) {
    $('proceed-link').addEventListener('click', function(event) {
      sendCommand(CMD_PROCEED);
    });
  } else {
    $('final-paragraph').classList.add('hidden');
  }

  if ($('help-link')) {
    $('help-link').addEventListener('click', function(event) {
      sendCommand(CMD_OPEN_DIAGNOSTIC);
    });
  }

  $('details-button').addEventListener('click', function(event) {
    var hiddenDetails = $('details').classList.toggle('hidden');

    if (mobileNav)
      $('main-content').classList.toggle('hidden', !hiddenDetails);
    else
      $('main-content').classList.remove('hidden');

    $('details-button').innerText = hiddenDetails ?
        'Details' :
        'Hide details';
    if (!expandedDetails) {
      // Record a histogram entry only the first time that details is opened.
      sendCommand(CMD_SHOW_MORE_SECTION);
      expandedDetails = true;
    }
  });
}

document.addEventListener('DOMContentLoaded', setupEvents);
