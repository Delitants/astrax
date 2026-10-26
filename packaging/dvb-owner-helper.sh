#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) Delitants

[ "$#" -eq 0 ] || { echo 'DVB ownership helper accepts no arguments' >&2; exit 2; }
exec /usr/bin/sudo -n -- /opt/astrax/astrax-dvb-owners
