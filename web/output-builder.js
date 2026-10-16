// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

// Pure output construction shared by External and structured DVB editors.
export function sanitizeMPEGTSPath(raw) {
  const path = String(raw || '').trim();
  return path ? (path.startsWith('/') ? path : `/${path}`) : '/channel1';
}

export function parsePositiveInt(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? Math.floor(number) : fallback;
}

function playPort(value, fallback) {
  const port = Number(value || fallback);
  return Number.isFinite(port) && port > 0 && port <= 65535 ? port : fallback;
}

export function buildMPEGTSOutputURL(values, settings = {}, hostname = '127.0.0.1', protocol = 'mpegts') {
  return `${protocol.endsWith('-secure') ? 'https' : 'http'}://${hostname || '127.0.0.1'}:${playPort(settings.http_play_port, 8000)}${sanitizeMPEGTSPath(values.mpegts_path)}`;
}

export function buildHLSOutputURL(values, settings = {}, hostname = '127.0.0.1', protocol = 'hls') {
  let path = sanitizeMPEGTSPath(values.mpegts_path);
  if (!path.endsWith('.m3u8')) path += '.m3u8';
  return buildMPEGTSOutputURL({...values, mpegts_path:path}, settings, hostname, protocol);
}

export function buildSRTOutputURL(values, settings = {}) {
  const mode = values.srt_mode === 'caller' ? 'caller' : 'listener';
  const host = String(values.srt_host || '').trim() || (mode === 'caller' ? '127.0.0.1' : '0.0.0.0');
  const port = parsePositiveInt(values.srt_port_override, 0) || playPort(settings.srt_play_port, 9000);
  const query = new URLSearchParams({mode});
  const streamid = String(values.srt_streamid || '').trim();
  if (streamid) query.set('streamid', streamid);
  query.set('latency', String(parsePositiveInt(values.srt_latency, 120)));
  const passphrase = String(values.srt_passphrase || '').trim();
  if (passphrase) {
    query.set('passphrase', passphrase);
    query.set('pbkeylen', String(parsePositiveInt(values.srt_pbkeylen, 16)));
  }
  if (values.srt_fec_enabled) query.set('packetfilter', `fec,cols:${parsePositiveInt(values.srt_fec_cols, 10)},rows:${parsePositiveInt(values.srt_fec_rows, 8)}`);
  return `srt://${host}:${port}?${query}`;
}

export function buildUDPOutputURL(values) {
  return `udp://${String(values.udp_host || '').trim() || '127.0.0.1'}:${parsePositiveInt(values.udp_port, 1234)}`;
}

export function buildOutputURL(protocol, values, settings = {}, hostname = '127.0.0.1') {
  if (protocol === 'mpegts' || protocol === 'mpegts-secure') return buildMPEGTSOutputURL(values, settings, hostname, protocol);
  if (protocol === 'hls' || protocol === 'hls-secure') return buildHLSOutputURL(values, settings, hostname, protocol);
  if (protocol === 'srt') return buildSRTOutputURL(values, settings);
  if (protocol === 'udp') return buildUDPOutputURL(values);
  return String(values.output_url || '').trim();
}

export function parseOutputURL(raw, protocol, settings = {}) {
  const values = {output_url:raw || '', mpegts_path:'/channel1', srt_mode:'listener', srt_host:'0.0.0.0', srt_port_override:'', srt_streamid:'', srt_passphrase:'', srt_pbkeylen:'16', srt_latency:'120', srt_fec_enabled:false, srt_fec_cols:'10', srt_fec_rows:'8', udp_host:'127.0.0.1', udp_port:''};
  try {
    const url = new URL(raw);
    if (['mpegts','mpegts-secure','hls','hls-secure'].includes(protocol)) {
      const path = url.pathname || '/channel1';
      values.mpegts_path = sanitizeMPEGTSPath(path.endsWith('.m3u8') ? path.slice(0, -5) : path);
    } else if (protocol === 'srt') {
      const query = url.searchParams;
      values.srt_mode = query.get('mode') === 'caller' ? 'caller' : 'listener';
      values.srt_host = url.hostname || (values.srt_mode === 'caller' ? '127.0.0.1' : '0.0.0.0');
      values.srt_port_override = Number(url.port) > 0 && Number(url.port) !== playPort(settings.srt_play_port, 9000) ? url.port : '';
      for (const [field, key] of [['srt_streamid','streamid'],['srt_passphrase','passphrase'],['srt_pbkeylen','pbkeylen'],['srt_latency','latency']]) values[field] = query.get(key) || values[field];
      const filter = (query.get('packetfilter') || '').toLowerCase();
      values.srt_fec_enabled = filter.includes('fec');
      if (values.srt_fec_enabled) {
        values.srt_fec_cols = String(Number(filter.match(/cols:(\d+)/)?.[1] || 10));
        values.srt_fec_rows = String(Number(filter.match(/rows:(\d+)/)?.[1] || 8));
      }
    } else if (protocol === 'udp') {
      values.udp_host = url.hostname || '127.0.0.1'; values.udp_port = url.port || '';
    }
  } catch { /* Invalid existing URLs retain the established form defaults. */ }
  return values;
}
