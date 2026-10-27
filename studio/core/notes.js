// An entry's About text: a summary of two or three sentences, then notes in labelled sections.
// Parser entries, playbooks and connectors all use it.
//
// Notes are plain text, read line by line:
//   a line that ends with a colon and holds nothing else   a section label, such as "Field mapping:"
//   a line that starts with "- "                           a bullet
//   a blank line                                           the end of a list or section
//   any other line                                         a paragraph
// Nothing in the text is markup. The page sets every block as text, so <b> or ** shows as typed.

export const SUMMARY_MAX = 500;
export const NOTES_MAX = 3000;
export const NOTE_LINE_MAX = 600;
export const NOTE_LABEL = /^([A-Z][^:\n]{0,47}):$/;
// The usual sections, in the usual order. Other labels are allowed.
export const NOTE_SECTIONS = ['Setup', 'Field mapping', 'Time', 'Sources and licenses', 'Made up in the samples', 'Testing', 'Known gaps'];
export const AUTOMATION_NOTE_SECTIONS = ['Setup', 'How it works', 'Testing', 'Known gaps'];

// What a summary says, and the sections to suggest, for each kind of entry.
const KINDS = {
  parser: {
    summary: 'say what data the parsers read, how it reaches Sophos NG-SIEM (syslog to the data collector, HTTP Ingest, a bridge), and which schemas it lands in',
    labels: '"Setup:" or "Field mapping:"',
  },
  playbook: {
    summary: 'say what the playbook does, what starts it and which connectors it calls, and what it needs',
    labels: '"Setup:" or "Testing:"',
  },
  connector: {
    summary: 'say what the connector calls and can do, how its connection signs in, and what it needs',
    labels: '"How it works:" or "Testing:"',
  },
};

// [{type: 'label', text}, {type: 'list', items: [text]}, {type: 'para', text}]
export function noteBlocks(text) {
  const blocks = [];
  let list = null;
  for (const raw of String(text ?? '').replace(/\r\n?/g, '\n').split('\n')) {
    const line = raw.trim();
    if (!line) { list = null; continue; }
    const bullet = /^-\s+(\S.*)$/.exec(line);
    if (bullet) {
      if (!list) { list = { type: 'list', items: [] }; blocks.push(list); }
      list.items.push(bullet[1]);
      continue;
    }
    list = null;
    const label = NOTE_LABEL.exec(line);
    blocks.push(label ? { type: 'label', text: label[1] } : { type: 'para', text: line });
  }
  return blocks;
}

// Rough sentence count: a full stop, question or exclamation mark followed by a space and a
// capital letter or digit, or the end of the text.
export function sentenceCount(text) {
  const s = String(text ?? '').trim();
  if (!s) return 0;
  return (s.match(/[.!?](?=\s+[A-Z0-9("]|\s*$)/g) || []).length || 1;
}

// Problems with an entry's summary and notes, as {level, message}. required: whether a missing
// summary or unlabelled notes are errors (true) or warnings. kind: parser, playbook or connector.
export function aboutProblems(meta, { required = true, kind = 'parser' } = {}) {
  const k = KINDS[kind] || KINDS.parser;
  const out = [];
  const err = (message) => out.push({ level: 'error', message });
  const need = (message) => out.push({ level: required ? 'error' : 'warning', message });
  const { summary, notes } = meta;
  if (summary === undefined || summary === null || (typeof summary === 'string' && !summary.trim())) {
    need(`summary is required: two or three plain sentences that ${k.summary}`);
  } else if (typeof summary !== 'string') {
    err('summary must be text');
  } else {
    if (summary.length > SUMMARY_MAX) err(`summary must be up to ${SUMMARY_MAX} characters; put the detail in notes`);
    if (/[\r\n]/.test(summary)) err('summary must be one paragraph, with no line breaks');
    if (sentenceCount(summary) > 3) out.push({ level: 'warning', message: 'summary reads as more than three sentences; keep it to two or three and put the detail in notes' });
  }
  if (notes === undefined || notes === null || notes === '') return out;
  if (typeof notes !== 'string' || notes.length > NOTES_MAX) { err(`notes must be text up to ${NOTES_MAX} characters`); return out; }
  const blocks = noteBlocks(notes);
  if (blocks.length && blocks[0].type !== 'label') need(`notes must start with a section label on its own line, such as ${k.labels}, with "- " bullets under it`);
  blocks.forEach((b, i) => {
    if (b.type === 'label' && (!blocks[i + 1] || blocks[i + 1].type === 'label')) err(`notes: the section "${b.text}:" has nothing under it`);
  });
  const long = blocks.flatMap((b) => (b.type === 'list' ? b.items : b.type === 'para' ? [b.text] : [])).filter((t) => t.length > NOTE_LINE_MAX);
  if (long.length) need(`notes: ${long.length === 1 ? 'a bullet or paragraph is' : `${long.length} bullets or paragraphs are`} over ${NOTE_LINE_MAX} characters; split ${long.length === 1 ? 'it' : 'them'} up`);
  if (/^\s*([*+•]\s|#{1,6}\s|>\s|\d+\.\s)/m.test(notes)) {
    out.push({ level: 'warning', message: 'notes are plain text: start bullets with "- " and sections with a "Label:" line. Other list and heading marks show as typed.' });
  }
  return out;
}
