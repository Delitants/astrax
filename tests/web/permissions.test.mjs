// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants
import test from 'node:test';
import assert from 'node:assert/strict';
import {permissionsFor, canAccessPage} from '../../web/permissions.js';

test('roles expose only monitoring, stream control and administrator pages', () => {
  for (const role of ['administrator','operator','viewer']) {
    const user = {username:'example',role,enabled:true};
    assert.equal(permissionsFor(user).manage,role === 'administrator');
    assert.equal(permissionsFor(user).control,role !== 'viewer');
    for (const page of ['overview','streams','dvb-cards','dvb-streams','account']) assert.equal(canAccessPage(user,page),true);
    for (const page of ['settings','softcams','api','logs','users','epg']) assert.equal(canAccessPage(user,page),role === 'administrator');
    assert.equal(canAccessPage(user,'unknown'),false);
  }
  for (const user of [null,{}, {role:'administrator',enabled:false}, {role:'unknown',enabled:true}]) {
    assert.deepEqual(permissionsFor(user),{manage:false,control:false});
    assert.equal(canAccessPage(user,'overview'),false);
  }
});
