import { parseTimestamp, SEVERITY_RANK } from '../utils/eventSchema.js';

export const SUPPORTED_FIELDS = [
  'eventId',
  'timestamp',
  'source',
  'eventType',
  'severity',
  'host',
  'username',
  'sourceIp',
  'destinationIp',
  'domain',
  'processName',
  'parentProcess',
  'commandLine',
  'action',
  'result',
  'message',
  'tags'
];

export const EXAMPLE_QUERIES = [
  {
    label: 'Authentication events',
    query: 'eventType = "authentication"'
  },
  {
    label: 'Failed logins for analyst.test',
    query: 'username = "analyst.test" AND result = "failure"'
  },
  {
    label: 'Auth from external IP',
    query: 'sourceIp = "198.51.100.24" AND eventType = "authentication"'
  },
  {
    label: 'High or Critical severity',
    query: 'severity IN ("high", "critical")'
  },
  {
    label: 'PowerShell execution',
    query: 'processName CONTAINS "powershell"'
  },
  {
    label: 'DNS or Outbound Proxy',
    query: '(eventType = "dns_query" OR eventType = "web_proxy") AND NOT result = "blocked"'
  }
];

/**
 * Tokenizes a structured query string into typed tokens.
 * Never executes arbitrary JS.
 */
export function tokenizeQuery(input) {
  if (typeof input !== 'string') {
    throw new Error('Query must be a string.');
  }
  const tokens = [];
  let i = 0;
  const len = input.length;

  while (i < len) {
    const ch = input[i];

    // Whitespace
    if (/\s/.test(ch)) {
      i++;
      continue;
    }

    // Parentheses and comma
    if (ch === '(') {
      tokens.push({ type: 'LPAREN', value: '(', pos: i });
      i++;
      continue;
    }
    if (ch === ')') {
      tokens.push({ type: 'RPAREN', value: ')', pos: i });
      i++;
      continue;
    }
    if (ch === ',') {
      tokens.push({ type: 'COMMA', value: ',', pos: i });
      i++;
      continue;
    }

    // Two-character comparison operators
    const twoChar = input.slice(i, i + 2);
    if (twoChar === '!=' || twoChar === '>=' || twoChar === '<=' || twoChar === '==') {
      tokens.push({
        type: 'OPERATOR',
        value: twoChar === '==' ? '=' : twoChar,
        pos: i
      });
      i += 2;
      continue;
    }

    // Single-character comparison operators
    if (ch === '=' || ch === '>' || ch === '<') {
      tokens.push({ type: 'OPERATOR', value: ch, pos: i });
      i++;
      continue;
    }

    // Quoted string literal
    if (ch === '"' || ch === "'") {
      const quote = ch;
      const start = i;
      i++;
      let str = '';
      let closed = false;
      while (i < len) {
        if (input[i] === '\\' && i + 1 < len) {
          str += input[i + 1];
          i += 2;
          continue;
        }
        if (input[i] === quote) {
          closed = true;
          i++;
          break;
        }
        str += input[i];
        i++;
      }
      if (!closed) {
        throw new Error(`Unterminated string literal starting at position ${start + 1}.`);
      }
      tokens.push({ type: 'STRING', value: str, pos: start });
      continue;
    }

    // Identifiers, keywords, numbers, or unquoted ISO timestamps/IPs
    if (/[a-zA-Z0-9_.:-]/.test(ch)) {
      const start = i;
      let word = '';
      while (i < len && /[a-zA-Z0-9_.:+-]/.test(input[i])) {
        word += input[i];
        i++;
      }
      const upper = word.toUpperCase();
      if (upper === 'AND' || upper === 'OR' || upper === 'NOT') {
        tokens.push({ type: upper, value: upper, pos: start });
      } else if (upper === 'CONTAINS' || upper === 'IN') {
        tokens.push({ type: 'OPERATOR', value: upper, pos: start });
      } else if (/^-?\d+(\.\d+)?$/.test(word)) {
        tokens.push({ type: 'NUMBER', value: Number(word), pos: start });
      } else {
        tokens.push({ type: 'IDENTIFIER', value: word, pos: start });
      }
      continue;
    }

    throw new Error(`Unexpected character "${ch}" at position ${i + 1}.`);
  }

  return tokens;
}

/**
 * Recursive-descent parser converting token stream into an AST.
 * Grammar:
 *   Expr       -> OrExpr
 *   OrExpr     -> AndExpr ( 'OR' AndExpr )*
 *   AndExpr    -> NotExpr ( 'AND' NotExpr )*
 *   NotExpr    -> 'NOT' NotExpr | Primary
 *   Primary    -> '(' Expr ')' | Comparison
 *   Comparison -> IDENTIFIER OPERATOR ValueOrList
 */
export function parseQuery(queryString) {
  if (!queryString || !queryString.trim()) {
    return null;
  }
  const tokens = tokenizeQuery(queryString);
  if (tokens.length === 0) return null;

  let cursor = 0;

  function peek() {
    return tokens[cursor] || null;
  }

  function consume(expectedType) {
    const tok = tokens[cursor];
    if (!tok) {
      throw new Error(`Unexpected end of query. Expected ${expectedType}.`);
    }
    if (expectedType && tok.type !== expectedType) {
      throw new Error(
        `Syntax error at position ${tok.pos + 1}: expected ${expectedType} but found "${tok.value}".`
      );
    }
    cursor++;
    return tok;
  }

  function parseExpr() {
    return parseOr();
  }

  function parseOr() {
    let left = parseAnd();
    while (peek() && peek().type === 'OR') {
      consume('OR');
      const right = parseAnd();
      left = { type: 'LogicalExpression', operator: 'OR', left, right };
    }
    return left;
  }

  function parseAnd() {
    let left = parseNot();
    while (peek() && peek().type === 'AND') {
      consume('AND');
      const right = parseNot();
      left = { type: 'LogicalExpression', operator: 'AND', left, right };
    }
    return left;
  }

  function parseNot() {
    if (peek() && peek().type === 'NOT') {
      consume('NOT');
      const argument = parseNot();
      return { type: 'UnaryExpression', operator: 'NOT', argument };
    }
    return parsePrimary();
  }

  function parsePrimary() {
    const tok = peek();
    if (!tok) {
      throw new Error('Unexpected end of query expression.');
    }
    if (tok.type === 'LPAREN') {
      consume('LPAREN');
      if (peek() && peek().type === 'RPAREN') {
        throw new Error(`Empty parentheses at position ${tok.pos + 1}.`);
      }
      const expr = parseExpr();
      if (!peek() || peek().type !== 'RPAREN') {
        throw new Error(`Missing closing parenthesis ")" for "(" at position ${tok.pos + 1}.`);
      }
      consume('RPAREN');
      return expr;
    }
    return parseComparison();
  }

  function parseScalarValue() {
    const tok = peek();
    if (!tok) {
      throw new Error('Expected a value after operator, but reached end of query.');
    }
    if (tok.type === 'STRING' || tok.type === 'NUMBER' || tok.type === 'IDENTIFIER') {
      cursor++;
      return tok.value;
    }
    throw new Error(
      `Expected a string or number value at position ${tok.pos + 1}, found "${tok.value}".`
    );
  }

  function parseComparison() {
    const fieldTok = peek();
    if (!fieldTok || fieldTok.type !== 'IDENTIFIER') {
      throw new Error(
        fieldTok
          ? `Expected a field name at position ${fieldTok.pos + 1}, found "${fieldTok.value}".`
          : 'Expected a field name.'
      );
    }
    consume('IDENTIFIER');

    const opTok = peek();
    if (!opTok || opTok.type !== 'OPERATOR') {
      throw new Error(
        opTok
          ? `Expected an operator (=, !=, CONTAINS, IN, >, <) after "${fieldTok.value}" at position ${opTok.pos + 1}, found "${opTok.value}".`
          : `Expected an operator after field "${fieldTok.value}".`
      );
    }
    consume('OPERATOR');

    if (opTok.value === 'IN') {
      const lp = peek();
      if (!lp || lp.type !== 'LPAREN') {
        throw new Error(
          `Expected "(" after IN operator at position ${opTok.pos + 1}. Example: severity IN ("high", "critical")`
        );
      }
      consume('LPAREN');
      const values = [];
      values.push(parseScalarValue());
      while (peek() && peek().type === 'COMMA') {
        consume('COMMA');
        values.push(parseScalarValue());
      }
      if (!peek() || peek().type !== 'RPAREN') {
        throw new Error('Expected closing ")" after IN list.');
      }
      consume('RPAREN');
      return {
        type: 'ComparisonExpression',
        field: fieldTok.value,
        operator: 'IN',
        value: values
      };
    }

    const val = parseScalarValue();
    return {
      type: 'ComparisonExpression',
      field: fieldTok.value,
      operator: opTok.value,
      value: val
    };
  }

  const ast = parseExpr();
  if (cursor < tokens.length) {
    const extra = tokens[cursor];
    throw new Error(`Unexpected token "${extra.value}" at position ${extra.pos + 1}.`);
  }
  return ast;
}

/**
 * Safely resolves a field value on an event object, supporting dotted metadata access.
 */
export function resolveEventField(event, fieldPath) {
  if (!event || typeof event !== 'object') return undefined;
  if (Object.prototype.hasOwnProperty.call(event, fieldPath)) {
    return event[fieldPath];
  }
  if (fieldPath.includes('.')) {
    const parts = fieldPath.split('.');
    let current = event;
    for (const part of parts) {
      if (part === '__proto__' || part === 'constructor' || part === 'prototype') {
        return undefined;
      }
      if (current && typeof current === 'object' && Object.prototype.hasOwnProperty.call(current, part)) {
        current = current[part];
      } else {
        return undefined;
      }
    }
    return current;
  }
  return undefined;
}

function compareValues(fieldName, rawEventVal, operator, targetVal) {
  if (rawEventVal === undefined || rawEventVal === null) {
    return operator === '!=' ? true : false;
  }

  // Handle array fields (e.g. tags)
  if (Array.isArray(rawEventVal)) {
    const lowerTarget = String(targetVal).toLowerCase();
    const lowerArr = rawEventVal.map((v) => String(v).toLowerCase());
    if (operator === '=' || operator === 'CONTAINS') {
      return lowerArr.some((item) =>
        operator === '=' ? item === lowerTarget : item.includes(lowerTarget)
      );
    }
    if (operator === '!=') {
      return !lowerArr.includes(lowerTarget);
    }
    if (operator === 'IN' && Array.isArray(targetVal)) {
      const targetSet = new Set(targetVal.map((v) => String(v).toLowerCase()));
      return lowerArr.some((item) => targetSet.has(item));
    }
    return false;
  }

  // Handle IN operator
  if (operator === 'IN') {
    if (!Array.isArray(targetVal)) return false;
    const eventStr = String(rawEventVal).toLowerCase();
    return targetVal.some((v) => String(v).toLowerCase() === eventStr);
  }

  // Handle CONTAINS operator
  if (operator === 'CONTAINS') {
    return String(rawEventVal).toLowerCase().includes(String(targetVal).toLowerCase());
  }

  // Handle >, <, >=, <=
  if (operator === '>' || operator === '<' || operator === '>=' || operator === '<=') {
    // Check timestamp comparison
    if (fieldName === 'timestamp' || (typeof rawEventVal === 'string' && parseTimestamp(rawEventVal) !== null)) {
      const leftMs = parseTimestamp(String(rawEventVal));
      const rightMs = parseTimestamp(String(targetVal));
      if (leftMs !== null && rightMs !== null) {
        if (operator === '>') return leftMs > rightMs;
        if (operator === '<') return leftMs < rightMs;
        if (operator === '>=') return leftMs >= rightMs;
        if (operator === '<=') return leftMs <= rightMs;
      }
    }

    // Check severity comparison
    if (fieldName === 'severity') {
      const leftRank = SEVERITY_RANK[String(rawEventVal).toLowerCase()];
      const rightRank = SEVERITY_RANK[String(targetVal).toLowerCase()];
      if (leftRank !== undefined && rightRank !== undefined) {
        if (operator === '>') return leftRank > rightRank;
        if (operator === '<') return leftRank < rightRank;
        if (operator === '>=') return leftRank >= rightRank;
        if (operator === '<=') return leftRank <= rightRank;
      }
    }

    // Numeric comparison
    const leftNum = Number(rawEventVal);
    const rightNum = Number(targetVal);
    if (!Number.isNaN(leftNum) && !Number.isNaN(rightNum)) {
      if (operator === '>') return leftNum > rightNum;
      if (operator === '<') return leftNum < rightNum;
      if (operator === '>=') return leftNum >= rightNum;
      if (operator === '<=') return leftNum <= rightNum;
    }

    // Fallback lexical comparison
    const leftStr = String(rawEventVal).toLowerCase();
    const rightStr = String(targetVal).toLowerCase();
    if (operator === '>') return leftStr > rightStr;
    if (operator === '<') return leftStr < rightStr;
    if (operator === '>=') return leftStr >= rightStr;
    if (operator === '<=') return leftStr <= rightStr;
  }

  // Equality / Inequality (case-insensitive for strings)
  const isEqual = String(rawEventVal).toLowerCase() === String(targetVal).toLowerCase();
  if (operator === '=') return isEqual;
  if (operator === '!=') return !isEqual;

  return false;
}

/**
 * Evaluates a parsed AST against a single security event.
 */
export function evaluateQueryAst(ast, event) {
  if (!ast) return true;

  switch (ast.type) {
    case 'LogicalExpression': {
      if (ast.operator === 'AND') {
        return evaluateQueryAst(ast.left, event) && evaluateQueryAst(ast.right, event);
      }
      if (ast.operator === 'OR') {
        return evaluateQueryAst(ast.left, event) || evaluateQueryAst(ast.right, event);
      }
      return false;
    }
    case 'UnaryExpression': {
      if (ast.operator === 'NOT') {
        return !evaluateQueryAst(ast.argument, event);
      }
      return false;
    }
    case 'ComparisonExpression': {
      const val = resolveEventField(event, ast.field);
      return compareValues(ast.field, val, ast.operator, ast.value);
    }
    default:
      return false;
  }
}

/**
 * Executes a structured query string against an array of events.
 * Returns { results, error, ast }.
 */
export function executeStructuredQuery(events, queryString) {
  if (!Array.isArray(events)) {
    return { results: [], error: 'Invalid event dataset.', ast: null };
  }
  if (!queryString || !queryString.trim()) {
    return { results: events, error: null, ast: null };
  }
  try {
    const ast = parseQuery(queryString);
    const results = events.filter((ev) => evaluateQueryAst(ast, ev));
    return { results, error: null, ast };
  } catch (err) {
    return {
      results: [],
      error: err.message || 'Invalid query syntax.',
      ast: null
    };
  }
}

/**
 * Combines structured query, free-text search, field filters, and sorting.
 */
export function filterAndQueryEvents(events, options = {}) {
  const {
    structuredQuery = '',
    freeText = '',
    source = 'all',
    severity = 'all',
    eventType = 'all',
    host = 'all',
    username = 'all',
    ipOrDomain = '',
    startTime = '',
    endTime = '',
    sortOrder = 'asc'
  } = options;

  let filtered = Array.isArray(events) ? [...events] : [];
  let queryError = null;

  if (structuredQuery && structuredQuery.trim()) {
    const qRes = executeStructuredQuery(filtered, structuredQuery);
    if (qRes.error) {
      return { events: [], total: 0, error: qRes.error };
    }
    filtered = qRes.results;
  }

  if (source && source !== 'all') {
    filtered = filtered.filter((e) => e.source === source);
  }

  if (severity && severity !== 'all') {
    filtered = filtered.filter((e) => e.severity === severity);
  }

  if (eventType && eventType !== 'all') {
    filtered = filtered.filter((e) => e.eventType === eventType);
  }

  if (host && host !== 'all') {
    filtered = filtered.filter((e) => e.host === host);
  }

  if (username && username !== 'all') {
    filtered = filtered.filter((e) => e.username === username);
  }

  if (ipOrDomain && ipOrDomain.trim()) {
    const needle = ipOrDomain.trim().toLowerCase();
    filtered = filtered.filter(
      (e) =>
        (e.sourceIp && e.sourceIp.toLowerCase().includes(needle)) ||
        (e.destinationIp && e.destinationIp.toLowerCase().includes(needle)) ||
        (e.domain && e.domain.toLowerCase().includes(needle))
    );
  }

  if (startTime) {
    const startMs = parseTimestamp(startTime);
    if (startMs !== null) {
      filtered = filtered.filter((e) => {
        const ms = parseTimestamp(e.timestamp);
        return ms !== null && ms >= startMs;
      });
    }
  }

  if (endTime) {
    const endMs = parseTimestamp(endTime);
    if (endMs !== null) {
      filtered = filtered.filter((e) => {
        const ms = parseTimestamp(e.timestamp);
        return ms !== null && ms <= endMs;
      });
    }
  }

  if (freeText && freeText.trim()) {
    const term = freeText.trim().toLowerCase();
    filtered = filtered.filter((e) => {
      const searchable = [
        e.eventId,
        e.source,
        e.eventType,
        e.severity,
        e.host,
        e.username,
        e.sourceIp,
        e.destinationIp,
        e.domain,
        e.processName,
        e.parentProcess,
        e.commandLine,
        e.action,
        e.result,
        e.message,
        ...(Array.isArray(e.tags) ? e.tags : [])
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      return searchable.includes(term);
    });
  }

  filtered.sort((a, b) => {
    const msA = parseTimestamp(a.timestamp) ?? 0;
    const msB = parseTimestamp(b.timestamp) ?? 0;
    return sortOrder === 'desc' ? msB - msA : msA - msB;
  });

  return {
    events: filtered,
    total: filtered.length,
    error: queryError
  };
}
