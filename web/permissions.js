// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

const roles = ['administrator', 'operator', 'viewer'];
const monitoringPages = ['overview', 'streams', 'dvb-cards', 'dvb-streams', 'account'];
const administratorPages = ['softcams', 'epg', 'api', 'settings', 'logs', 'users'];
const valid = user => user?.enabled === true && roles.includes(user.role);

// Presentation follows the server principal; the HTTP boundary independently
// enforces every permission, including requests made outside this interface.
export function permissionsFor(user) {
  return {manage: valid(user) && user.role === 'administrator', control: valid(user) && user.role !== 'viewer'};
}

export function canAccessPage(user, page) {
  return valid(user) && (monitoringPages.includes(page) || user.role === 'administrator' && administratorPages.includes(page));
}
