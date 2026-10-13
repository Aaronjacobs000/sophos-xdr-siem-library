// Lookups over the generated schema data.

import data from './schema-data.js';

export const SCHEMA_DATA = data;
export const GENERIC = 'scwx.generic';
export const SCALARS = new Set(['string', 'bool', 'uint32', 'uint64', 'int32', 'int64', 'sint32', 'sint64', 'float', 'double', 'bytes']);
export const INT_TYPES = new Set(['uint32', 'uint64', 'int32', 'int64', 'sint32', 'sint64']);

// The generic schema has no page of its own; the overview lists its common fields.
const GENERIC_FIELDS = [
  { name: 'sensor_type', type: 'string', parser: 'sensorType$' },
  { name: 'sensor_id', type: 'string', parser: 'sensorId$' },
  { name: 'host_id', type: 'string', parser: 'hostId$' },
  { name: 'event_time_usec', type: 'uint64', parser: 'eventTimeUsec$' },
];

export const SCHEMA_IDS = [GENERIC, ...Object.keys(data.schemas)];

// Fields the engine stores that the docs' schema tables leave out (checked in a lab tenant). The
// engine maps a $ variable only to a field its schema has: eventType$ became event_type in
// Antivirus but was dropped in eleven other schemas.
const ENGINE_FIELDS = {
  'scwx.antivirus': [
    { name: 'event_type', type: 'string', parser: 'eventType$', engineOnly: true },
    { name: 'sensor_version', type: 'string', parser: 'sensorVersion$', engineOnly: true },
    { name: 'source_address', type: 'string', parser: 'sourceAddress$', engineOnly: true },
  ],
  'scwx.managementevent': [
    { name: 'source_address', type: 'string', parser: 'sourceAddress$', engineOnly: true },
  ],
};

export function schemaInfo(id) {
  if (id === GENERIC) return { id, name: 'Generic', page: 'https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/CustomParsers/#generic-schema', documentedId: true, fields: GENERIC_FIELDS };
  const s = data.schemas[id];
  return s ? { id, ...s, fields: [...s.fields, ...(ENGINE_FIELDS[id] || [])] } : null;
}

const fieldIndex = new Map();
export function fieldsByParser(id) {
  if (!fieldIndex.has(id)) {
    const s = schemaInfo(id);
    fieldIndex.set(id, s ? new Map(s.fields.map((f) => [f.parser, f])) : new Map());
  }
  return fieldIndex.get(id);
}

export function enumMembers(type) {
  return data.types.enums[type] || null;
}

export function enumNumbers(type) {
  return (data.types.enumNumbers && data.types.enumNumbers[type]) || {};
}

export function messageType(type) {
  return data.types.messages[type] || null;
}

export function typeKind(type) {
  if (SCALARS.has(type)) return 'scalar';
  if (data.types.enums[type]) return 'enum';
  if (data.types.messages[type]) return 'message';
  return 'opaque';
}

export function subField(type, parserName) {
  const t = messageType(type);
  return t ? t.find((f) => f.parser === parserName) || null : null;
}

export function schemaIdFromName(name) {
  const lower = String(name).toLowerCase();
  for (const id of SCHEMA_IDS) if (id === lower || schemaInfo(id).name.toLowerCase() === lower) return id;
  return null;
}

export function hasEventMetadata(id) {
  return fieldsByParser(id).has('eventMetadata$');
}

// The docs' parser-field column misspells a few names; the engine only takes the rule name.
export function docMisspellings(id) {
  const s = schemaInfo(id);
  return s ? new Map(s.fields.filter((f) => f.docParser).map((f) => [f.docParser, f.parser])) : new Map();
}
