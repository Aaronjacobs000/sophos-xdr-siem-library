// Go time.Parse layouts (reference time Mon Jan 2 15:04:05 MST 2006) in JavaScript.
// The chunk rules follow Go's time/format.go so layouts behave the way the Sophos engine's
// DATETIME() would, including Go's quirks (no year in the layout means year 0).

import { TimeValue, RuntimeError } from './values.js';

const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

// Split a layout into literal text and std chunks, like Go's nextStdChunk.
export function layoutChunks(layout) {
  const out = [];
  let lit = '';
  const push = (std, len) => { if (lit) out.push({ lit }); lit = ''; out.push({ std }); return len; };
  for (let i = 0; i < layout.length;) {
    const r = layout.slice(i);
    const c = layout[i];
    let n = 0;
    switch (c) {
      case 'J':
        if (r.startsWith('January')) n = push('January', 7);
        else if (r.startsWith('Jan')) n = push('Jan', 3);
        break;
      case 'M':
        if (r.startsWith('Monday')) n = push('Monday', 6);
        else if (r.startsWith('Mon')) n = push('Mon', 3);
        else if (r.startsWith('MST')) n = push('MST', 3);
        break;
      case '0':
        if (/^0[1-6]/.test(r)) n = push(r.slice(0, 2), 2);
        else if (r.startsWith('002')) n = push('002', 3);
        break;
      case '1':
        if (r.startsWith('15')) n = push('15', 2);
        else n = push('1', 1);
        break;
      case '2':
        if (r.startsWith('2006')) n = push('2006', 4);
        else n = push('2', 1);
        break;
      case '_':
        if (r.startsWith('_2006')) { lit += '_'; n = 1; break; }
        if (r.startsWith('__2')) n = push('__2', 3);
        else if (r.startsWith('_2')) n = push('_2', 2);
        break;
      case '3': case '4': case '5':
        n = push(c, 1);
        break;
      case 'P':
        if (r.startsWith('PM')) n = push('PM', 2);
        break;
      case 'p':
        if (r.startsWith('pm')) n = push('pm', 2);
        break;
      case '-': {
        const m = /^-07(?::00:00|0000|:00|00)?/.exec(r);
        if (m) n = push(m[0], m[0].length);
        break;
      }
      case 'Z': {
        const m = /^Z07(?::00:00|0000|:00|00)?/.exec(r);
        if (m) n = push(m[0], m[0].length);
        break;
      }
      case '.': case ',': {
        const m = /^[.,](0+|9+)/.exec(r);
        if (m && !/[0-9]/.test(r[m[0].length] || '') && /[0-9]$/.test(layout.slice(0, i))) n = push(m[0], m[0].length);
        break;
      }
      default:
    }
    if (n) { i += n; continue; }
    lit += c;
    i++;
  }
  if (lit) out.push({ lit });
  return out;
}

function num(value, fixed, max = 2) {
  const m = fixed ? new RegExp(`^\\d{${max}}`).exec(value) : new RegExp(`^\\d{1,${max}}`).exec(value);
  if (!m) return null;
  return [Number(m[0]), value.slice(m[0].length)];
}

function lookup(value, list, short) {
  for (let i = 0; i < list.length; i++) {
    const name = short ? list[i].slice(0, 3) : list[i];
    if (value.slice(0, name.length).toLowerCase() === name.toLowerCase()) return [i, value.slice(name.length)];
  }
  return null;
}

const fail = (layout, value, why) => new RuntimeError(`DATETIME could not read "${value}" with layout "${layout}": ${why}`, 'datetime');

// Parse value with a Go layout. Returns a TimeValue. Throws RuntimeError on mismatch.
// opts.handle2DigitYear: when the value carries no year, pick one near opts.now, and drop the
// fractional seconds.
export function goParse(layout, value, opts = {}) {
  const chunks = layoutChunks(layout);
  let v = String(value);
  let year = null, month = 1, day = 1, hour = 0, minute = 0, second = 0, nanos = 0, yday = -1;
  let pm = null, offset = null, zone = null;
  let hasYear = false;
  for (let k = 0; k < chunks.length; k++) {
    const ch = chunks[k];
    if (ch.lit !== undefined) {
      // Go's skip(): a space in the layout matches any run of spaces in the value.
      let lit = ch.lit;
      while (lit.length) {
        if (lit[0] === ' ') {
          if (v.length && v[0] !== ' ') throw fail(layout, value, `expected a space at "${v}"`);
          lit = lit.replace(/^ +/, '');
          v = v.replace(/^ +/, '');
          continue;
        }
        if (!v.length || v[0] !== lit[0]) throw fail(layout, value, `expected "${ch.lit}" at "${v}"`);
        lit = lit.slice(1);
        v = v.slice(1);
      }
      continue;
    }
    const std = ch.std;
    let r;
    switch (std) {
      case '2006':
        if (!/^\d{4}/.test(v)) throw fail(layout, value, `expected a 4-digit year at "${v}"`);
        year = Number(v.slice(0, 4)); v = v.slice(4); hasYear = true; break;
      case '06':
        if (!/^\d{2}/.test(v)) throw fail(layout, value, `expected a 2-digit year at "${v}"`);
        year = Number(v.slice(0, 2)); year += year >= 69 ? 1900 : 2000; v = v.slice(2); hasYear = true; break;
      case 'January': case 'Jan':
        r = lookup(v, MONTHS, std === 'Jan');
        if (!r) throw fail(layout, value, `expected a month name at "${v}"`);
        month = r[0] + 1; v = r[1]; break;
      case 'Monday': case 'Mon':
        r = lookup(v, DAYS, std === 'Mon');
        if (!r) throw fail(layout, value, `expected a weekday at "${v}"`);
        v = r[1]; break;
      case '01': case '1':
        r = num(v, std === '01');
        if (!r || r[0] < 1 || r[0] > 12) throw fail(layout, value, 'month out of range');
        [month, v] = r; break;
      case '02': case '2': case '_2':
        if (std === '_2' && v[0] === ' ') v = v.slice(1);
        r = num(v, std === '02');
        if (!r || r[0] < 1 || r[0] > 31) throw fail(layout, value, 'day out of range');
        [day, v] = r; break;
      case '002': case '__2':
        if (std === '__2') v = v.replace(/^ {1,2}/, '');
        r = num(v, std === '002', 3);
        if (!r || r[0] < 1 || r[0] > 366) throw fail(layout, value, 'day of year out of range');
        [yday, v] = r; break;
      case '15':
        r = num(v, false);
        if (!r || r[0] > 23) throw fail(layout, value, 'hour out of range');
        [hour, v] = r; break;
      case '03': case '3':
        r = num(v, std === '03');
        if (!r || r[0] > 12) throw fail(layout, value, 'hour out of range');
        [hour, v] = r; break;
      case '04': case '4':
        r = num(v, std === '04');
        if (!r || r[0] > 59) throw fail(layout, value, 'minute out of range');
        [minute, v] = r; break;
      case '05': case '5':
        r = num(v, std === '05');
        if (!r || r[0] > 59) throw fail(layout, value, 'second out of range');
        [second, v] = r;
        // Go accepts a fractional second here even when the layout has none.
        if (/^[.,]\d/.test(v) && !(chunks[k + 1] && chunks[k + 1].std && /^[.,]/.test(chunks[k + 1].std))) {
          const m = /^[.,](\d+)/.exec(v);
          nanos = Number((m[1] + '000000000').slice(0, 9));
          v = v.slice(m[0].length);
        }
        break;
      case 'PM': case 'pm': {
        const s = v.slice(0, 2).toUpperCase();
        if (s !== 'AM' && s !== 'PM') throw fail(layout, value, 'expected AM or PM');
        pm = s === 'PM'; v = v.slice(2); break;
      }
      case 'MST': {
        const m = /^(UTC|GMT[+-]\d{1,2}|GMT|[A-Z]{3,5})/.exec(v);
        if (!m) throw fail(layout, value, `expected a zone abbreviation at "${v}"`);
        zone = m[1];
        if (zone.startsWith('GMT') && zone.length > 3) offset = Number(zone.slice(3)) * 60;
        else offset = 0; // Go gives an unknown abbreviation a zero offset.
        v = v.slice(m[0].length); break;
      }
      default:
        if (std.startsWith('-07') || std.startsWith('Z07')) {
          if (std[0] === 'Z' && v[0] === 'Z') { offset = 0; zone = 'UTC'; v = v.slice(1); break; }
          const shape = std.slice(1);
          const re = shape === '07:00:00' ? /^([+-])(\d{2}):(\d{2}):(\d{2})/ : shape === '070000' ? /^([+-])(\d{2})(\d{2})(\d{2})/
            : shape === '07:00' ? /^([+-])(\d{2}):(\d{2})/ : shape === '0700' ? /^([+-])(\d{2})(\d{2})/ : /^([+-])(\d{2})/;
          const m = re.exec(v);
          if (!m) throw fail(layout, value, `expected a zone offset at "${v}"`);
          offset = (m[1] === '-' ? -1 : 1) * (Number(m[2]) * 60 + Number(m[3] || 0));
          v = v.slice(m[0].length);
          break;
        }
        if (/^[.,](0+|9+)$/.test(std)) {
          const m = std[1] === '0' ? new RegExp(`^[.,](\\d{${std.length - 1}})`).exec(v) : /^[.,](\d+)/.exec(v);
          if (!m) {
            if (std[1] === '9') break;
            throw fail(layout, value, 'expected fractional seconds');
          }
          nanos = Number((m[1] + '000000000').slice(0, 9));
          v = v.slice(m[0].length);
          break;
        }
        throw fail(layout, value, `unsupported layout element ${std}`);
    }
  }
  if (v.length) throw fail(layout, value, `extra text "${v}"`);
  if (pm !== null) {
    if (pm && hour < 12) hour += 12;
    if (!pm && hour === 12) hour = 0;
  }
  let inferredYear = false;
  if (!hasYear) {
    if (opts.handle2DigitYear) {
      const now = opts.now ? new Date(opts.now) : new Date();
      year = now.getUTCFullYear();
      inferredYear = true;
    } else {
      year = 0;
    }
  }
  if (yday > 0) {
    const d = new Date(Date.UTC(2000, 0, 1));
    d.setUTCFullYear(year, 0, yday);
    month = d.getUTCMonth() + 1; day = d.getUTCDate();
  }
  const dt = new Date(Date.UTC(2000, 0, 1));
  dt.setUTCFullYear(year, month - 1, day);
  dt.setUTCHours(hour, minute, second, 0);
  if (dt.getUTCDate() !== day) throw fail(layout, value, 'day out of range for the month');
  let ms = dt.getTime() - (offset ?? 0) * 60000;
  if (inferredYear) {
    // Around new year a December log read in January belongs to last year.
    const now = opts.now ? new Date(opts.now).getTime() : Date.now();
    if (ms - now > 7 * 86400000) {
      dt.setUTCFullYear(year - 1);
      ms = dt.getTime() - (offset ?? 0) * 60000;
    }
  }
  // With handle2DigitYear the engine drops the fractional seconds, whatever the layout: TRUE turns
  // 22:21:09.461230 into 22:21:09 (checked in a lab tenant).
  const usec = ms * 1000 + (opts.handle2DigitYear ? 0 : Math.floor(nanos / 1000));
  return new TimeValue(usec, offset ?? 0, zone ?? (offset ? '' : 'UTC'));
}

// DATETIME(data) with no layout: try the common shapes. INFERRED: the docs call the layout
// optional but don't say what the engine tries without one.
// Checked in a lab tenant: RFC 3339 with Z, +01:00 or +0100, "2006-01-02 15:04:05",
// "01/02/2006 15:04:05", "Jan 02 2006 15:04:05", RFC 1123 and epoch seconds or milliseconds
// parse; a value with no year ("Sep 14 22:59:23") gets year 0.
const FALLBACK = [
  '2006-01-02T15:04:05Z07:00', '2006-01-02T15:04:05Z0700', '2006-01-02T15:04:05', '2006-01-02 15:04:05Z07:00',
  '2006-01-02 15:04:05', '01/02/2006 15:04:05', 'Mon, 02 Jan 2006 15:04:05 -0700', 'Mon, 02 Jan 2006 15:04:05 MST',
  'Jan _2 2006 15:04:05', 'Jan _2 15:04:05',
];

export function goParseAuto(value, opts = {}) {
  const s = String(value).trim();
  if (/^\d{10}(\.\d+)?$/.test(s)) return new TimeValue(Math.round(Number(s) * 1e6));
  if (/^\d{13}$/.test(s)) return new TimeValue(Number(s) * 1000);
  if (/^\d{16}$/.test(s)) return new TimeValue(Number(s));
  for (const layout of FALLBACK) {
    try { return goParse(layout, s, { ...opts, handle2DigitYear: false }); } catch { /* next */ }
  }
  throw new RuntimeError(`DATETIME could not read "${s}" without a layout; give it a Go layout`, 'datetime');
}

export function hasYear(layout) {
  return layoutChunks(layout).some((c) => c.std === '2006' || c.std === '06');
}

export function hasZone(layout) {
  return layoutChunks(layout).some((c) => c.std && (c.std === 'MST' || c.std.startsWith('-07') || c.std.startsWith('Z07')));
}
