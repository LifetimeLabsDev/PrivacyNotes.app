/**
 * Table formulas: the engine, with no editor and no DOM anywhere in it.
 *
 * A formula IS the cell's text. The note on disk keeps `=SUM(B2:B7)`, and
 * whoever draws the table paints the number over it. That is the only shape a
 * pipe table can carry: a GFM cell holds text and nothing else, so an
 * attribute on the cell node would not merely be dropped - it would push the
 * whole table out of `tableIsPipeSerializable` in editorTables.ts and store it
 * as a raw HTML blob from the next save onwards.
 *
 * Keeping the formula in the text buys three more things. The document needs
 * no schema change, so nothing migrates. The source cannot be lost, because
 * the source is all there is. And the drawn number can follow the reader's
 * language, because the stored bytes never hold a formatted result.
 *
 * Two callers draw from this one engine: the editor plugin
 * (editorTableFormula.ts) and the export renderer (markdownRender.ts), which
 * never loads TipTap. Both hand it the same thing, a grid of cell strings, and
 * get back a grid of results.
 *
 * Spec: ops/docs/archive/table-formulas.md
 */

/** A1 reference: column letters then a row number, as Capacities writes them. */
const REF_RE = /^([A-Za-z]+)(\d+)$/;

/**
 * What counts as a number in a cell.
 *
 * Deliberately narrow. `1,234.50` is accepted because a budget table is the
 * reported use and that is how English writes one; the comma must sit in
 * strict groups of three, so a German `1.234,56` fails the test and is SKIPPED
 * rather than read as 1.234. A skipped cell gives a total that is visibly too
 * low. A tolerant parser that guessed the separator would give a total that
 * looks right and is wrong, which is the worse failure by a long way.
 *
 * A leading or trailing currency symbol is allowed for the same reason: a
 * column of `$1,200` is the common case and nothing about it is ambiguous.
 */
const CURRENCY = /^[$€£¥]\s?|\s?[$€£¥]$/g;
const NUMBER_RE = /^-?(\d{1,3}(,\d{3})+|\d+)(\.\d+)?$/;

/**
 * The function set, matching Capacities name for name.
 *
 * Matching their list is what makes a Capacities importer a straight mapping
 * rather than a formula rewrite, so a name here is their name even where
 * another spreadsheet would call it something else: `AVG`, not Excel's
 * `AVERAGE`, and `CEIL`, not Excel's `CEILING`. `AVERAGE` is accepted as well,
 * because it is what a person types.
 *
 * Capacities documents the names and nothing else: no arity, no bases, no
 * error behaviour. Where it is silent, the choice is Excel's, on the reasoning
 * that Capacities is far more likely to have copied Excel than to have
 * invented something. Three of those choices are worth naming, because a wrong
 * guess is a silently wrong number rather than a visible failure:
 *
 * - `LOG` is base 10, as Excel's is. An optional second argument gives another
 *   base, which Excel also allows, so we are a superset either way.
 * - `ROUND` goes to a whole number, which is what Capacities describes. An
 *   optional second argument gives decimal places, again a superset.
 * - `CEIL` and `FLOOR` are plain `Math.ceil` and `Math.floor`, which is what
 *   Capacities describes. Excel's own CEILING and FLOOR take a significance
 *   argument and return an error without one, and that is NOT what is wanted.
 *
 * Spec: ops/docs/archive/table-formulas.md (section 4b)
 */

/** Takes every value in its arguments, ranges flattened. Non-numeric cells never arrive. */
const AGGREGATES: Record<string, (values: number[]) => number | null> = {
  SUM: (v) => v.reduce((a, b) => a + b, 0),
  PRODUCT: (v) => (v.length ? v.reduce((a, b) => a * b, 1) : null),
  AVG: (v) => (v.length ? v.reduce((a, b) => a + b, 0) / v.length : null),
  AVERAGE: (v) => (v.length ? v.reduce((a, b) => a + b, 0) / v.length : null),
  MEDIAN: (v) => {
    if (!v.length) return null;
    const sorted = [...v].sort((a, b) => a - b);
    const mid = sorted.length >> 1;
    return sorted.length % 2 ? sorted[mid]! : (sorted[mid - 1]! + sorted[mid]!) / 2;
  },
  MIN: (v) => (v.length ? Math.min(...v) : null),
  MAX: (v) => (v.length ? Math.max(...v) : null),
  // The only one with an answer over nothing, and the answer is zero.
  COUNT: (v) => v.length,
};

/**
 * Takes a fixed count of single values. A range handed to one of these is a
 * mistake rather than a shorthand, so it fails instead of quietly using the
 * first cell.
 */
const SCALARS: Record<string, { min: number; max: number; fn: (args: number[], random: () => number) => number | null }> = {
  ABS: { min: 1, max: 1, fn: ([x]) => Math.abs(x!) },
  SQRT: { min: 1, max: 1, fn: ([x]) => (x! < 0 ? null : Math.sqrt(x!)) },
  SIGN: { min: 1, max: 1, fn: ([x]) => Math.sign(x!) },
  CEIL: { min: 1, max: 1, fn: ([x]) => Math.ceil(x!) },
  FLOOR: { min: 1, max: 1, fn: ([x]) => Math.floor(x!) },
  ROUND: {
    min: 1,
    max: 2,
    fn: ([x, digits]) => {
      const places = digits === undefined ? 0 : Math.trunc(digits);
      if (places < 0 || places > 15) return null;
      return Number(x!.toFixed(places));
    },
  },
  LOG: {
    min: 1,
    max: 2,
    fn: ([x, base]) => {
      if (x! <= 0) return null;
      if (base === undefined) return Math.log10(x!);
      if (base <= 0 || base === 1) return null;
      return Math.log(x!) / Math.log(base);
    },
  },
  RAND: { min: 0, max: 0, fn: (_args, random) => random() },
};

/**
 * RAND has to hold still.
 *
 * Every other function is a pure reading of the grid, so re-running the whole
 * evaluation on each keystroke and each caret move costs nothing visible.
 * RAND has no inputs, so the same re-run would re-roll it constantly and the
 * number would never settle long enough to read. Each call site therefore
 * keeps its roll, keyed by the cell it sits in, the formula text and which
 * RAND in that formula it is. The number is then stable while the note is
 * open and rolls again on reload, which is the closest thing to a sensible
 * answer for a function whose honest output changes every time it is asked.
 *
 * The cap exists because the key includes the formula TEXT, so every
 * keystroke inside a formula containing RAND writes a new entry.
 */
const randomRolls = new Map<string, number>();

function stableRandom(key: string): number {
  const held = randomRolls.get(key);
  if (held !== undefined) return held;
  if (randomRolls.size > 500) randomRolls.clear();
  const rolled = Math.random();
  randomRolls.set(key, rolled);
  return rolled;
}

/**
 * Usable bare (`=PI*2`) and as a call (`=PI()`), because Capacities lists them
 * beside the functions and gives no sign of which form it takes.
 */
const CONSTANTS: Record<string, number> = {
  PI: Math.PI,
  E: Math.E,
  TAU: Math.PI * 2,
  // The golden ratio. Excel's PHI is the normal distribution's density
  // function and returns a completely different number under the same name,
  // which is why no Excel function library can be used here as-is.
  PHI: (1 + Math.sqrt(5)) / 2,
};

/** Every name the parser knows, for the insert menu and for error messages. */
export const FORMULA_NAMES: readonly string[] = [
  ...Object.keys(AGGREGATES),
  ...Object.keys(SCALARS),
  ...Object.keys(CONSTANTS),
];

export type FormulaResult = { value: number } | { error: true };

/** A cell's text is a formula when it starts with `=` and carries something after it. */
export function isFormulaText(text: string): boolean {
  const trimmed = text.trim();
  return trimmed.length > 1 && trimmed.startsWith('=');
}

/**
 * Read a cell's text as a number, or null when it is not one.
 *
 * Exported because the aggregate rule ("skip what is not a number") is the
 * same question the callers ask about a plain cell.
 */
export function cellNumber(text: string): number | null {
  const cleaned = text.trim().replace(CURRENCY, '');
  if (!NUMBER_RE.test(cleaned)) return null;
  const value = Number(cleaned.replace(/,/g, ''));
  return Number.isFinite(value) ? value : null;
}

/** Bijective base 26: A is 0, Z is 25, AA is 26. */
function columnIndex(letters: string): number {
  let index = 0;
  for (const ch of letters.toUpperCase()) index = index * 26 + (ch.charCodeAt(0) - 64);
  return index - 1;
}

type Token = { kind: 'num'; value: number } | { kind: 'ref'; row: number; col: number } | { kind: 'name'; value: string } | { kind: 'op'; value: string };

/**
 * Split a formula into tokens, or return null on any character we do not know.
 *
 * Returning null rather than throwing keeps one failure mode: the caller draws
 * the cell's own text, which is exactly what a reader without the feature
 * sees.
 */
function tokenize(source: string): Token[] | null {
  const tokens: Token[] = [];
  let i = 0;
  while (i < source.length) {
    const ch = source[i]!;
    if (/\s/.test(ch)) {
      i++;
      continue;
    }
    if ('+-*/(),:'.includes(ch)) {
      tokens.push({ kind: 'op', value: ch });
      i++;
      continue;
    }
    const number = /^(\d+(\.\d+)?|\.\d+)/.exec(source.slice(i));
    if (number) {
      tokens.push({ kind: 'num', value: Number(number[0]) });
      i += number[0].length;
      continue;
    }
    const word = /^[A-Za-z]+\d*/.exec(source.slice(i));
    if (!word) return null;
    const ref = REF_RE.exec(word[0]);
    // A word with a row number on it is a cell; a bare word is a function
    // name. `SUM` and `B2` are told apart by nothing else, which is why a
    // function may never end in a digit.
    tokens.push(ref ? { kind: 'ref', row: Number(ref[2]) - 1, col: columnIndex(ref[1]!) } : { kind: 'name', value: word[0].toUpperCase() });
    i += word[0].length;
  }
  return tokens;
}

/** Thrown inside the parser and the walk, never out of this module. */
class FormulaFailure extends Error {}

/**
 * A cycle, which is deliberately NOT a FormulaFailure.
 *
 * Every other failure stops at the cell that caused it, so a neighbour's
 * broken formula is skipped by a range and the rest of the column still
 * totals. A cycle cannot work that way: the cell that closes the loop would
 * be skipped as "not a number" and the cell that opened it would print a
 * confident total with one row silently missing. So this one travels all the
 * way out, and every cell in the loop shows its own text instead.
 */
class CycleError extends Error {}

/**
 * Recursive-descent parser and evaluator in one pass.
 *
 * One pass is enough because nothing here re-reads a sub-expression: there is
 * no assignment, no condition and no loop in the grammar. Building an AST
 * first would be a second representation with no reader.
 */
class Evaluator {
  private pos = 0;

  constructor(
    private readonly tokens: Token[],
    private readonly scalar: (row: number, col: number) => number,
    private readonly range: (a: { row: number; col: number }, b: { row: number; col: number }) => number[],
    private readonly random: () => number,
  ) {}

  run(): number {
    const value = this.expression();
    if (this.pos !== this.tokens.length) throw new FormulaFailure();
    return value;
  }

  private peek(): Token | undefined {
    return this.tokens[this.pos];
  }

  private eatOp(value: string): boolean {
    const token = this.peek();
    if (token?.kind === 'op' && token.value === value) {
      this.pos++;
      return true;
    }
    return false;
  }

  private expression(): number {
    let left = this.term();
    for (;;) {
      if (this.eatOp('+')) left += this.term();
      else if (this.eatOp('-')) left -= this.term();
      else return left;
    }
  }

  private term(): number {
    let left = this.factor();
    for (;;) {
      if (this.eatOp('*')) left *= this.factor();
      else if (this.eatOp('/')) {
        const divisor = this.factor();
        // A division by zero has no number to show, so the cell falls back to
        // its own text rather than printing Infinity.
        if (divisor === 0) throw new FormulaFailure();
        left /= divisor;
      } else return left;
    }
  }

  private factor(): number {
    if (this.eatOp('-')) return -this.factor();
    if (this.eatOp('+')) return this.factor();
    return this.primary();
  }

  private primary(): number {
    const token = this.peek();
    if (!token) throw new FormulaFailure();
    if (token.kind === 'num') {
      this.pos++;
      return token.value;
    }
    if (token.kind === 'ref') {
      this.pos++;
      // A range is only ever a function argument, so a `:` reached here (as in
      // `=B2:B7`) is a formula with no single value to show.
      if (this.eatOp(':')) throw new FormulaFailure();
      return this.scalar(token.row, token.col);
    }
    if (token.kind === 'name') {
      this.pos++;
      return this.call(token.value);
    }
    if (this.eatOp('(')) {
      const value = this.expression();
      if (!this.eatOp(')')) throw new FormulaFailure();
      return value;
    }
    throw new FormulaFailure();
  }

  private call(name: string): number {
    const constant = CONSTANTS[name];
    if (constant !== undefined) {
      // `PI` and `PI()` are the same thing. An argument is not.
      if (this.eatOp('(') && !this.eatOp(')')) throw new FormulaFailure();
      return constant;
    }

    const aggregate = AGGREGATES[name];
    if (aggregate) {
      if (!this.eatOp('(')) throw new FormulaFailure();
      const values: number[] = [];
      if (!this.eatOp(')')) {
        do values.push(...this.argument());
        while (this.eatOp(','));
        if (!this.eatOp(')')) throw new FormulaFailure();
      }
      return this.finish(aggregate(values));
    }

    const scalar = SCALARS[name];
    if (!scalar || !this.eatOp('(')) throw new FormulaFailure();
    const args: number[] = [];
    if (!this.eatOp(')')) {
      do {
        const values = this.argument();
        // A range inside ABS or ROUND is a mistake, not a shorthand for its
        // first cell. Failing here shows the formula, which says so.
        if (values.length !== 1) throw new FormulaFailure();
        args.push(values[0]!);
      } while (this.eatOp(','));
      if (!this.eatOp(')')) throw new FormulaFailure();
    }
    if (args.length < scalar.min || args.length > scalar.max) throw new FormulaFailure();
    return this.finish(scalar.fn(args, this.random));
  }

  /**
   * A function with no answer (MIN of nothing numeric, SQRT of a negative)
   * fails the whole formula, so the cell shows the text the user wrote.
   */
  private finish(result: number | null): number {
    if (result === null || !Number.isFinite(result)) throw new FormulaFailure();
    return result;
  }

  /** One argument: a range, which contributes many numbers, or an expression, which contributes one. */
  private argument(): number[] {
    const first = this.peek();
    const second = this.tokens[this.pos + 1];
    if (first?.kind === 'ref' && second?.kind === 'op' && second.value === ':') {
      const end = this.tokens[this.pos + 2];
      if (end?.kind !== 'ref') throw new FormulaFailure();
      this.pos += 3;
      return this.range(first, end);
    }
    return [this.expression()];
  }
}

/**
 * Evaluate every formula in a grid of cell strings.
 *
 * The returned grid is the same shape as the input. A cell that holds no
 * formula is null; a formula that cannot produce a number is `{ error: true }`,
 * and every caller draws those two the same way, as the cell's own text.
 *
 * Cells may reference cells that are themselves formulas. The walk memoises
 * each cell and marks the ones it is inside, so a cycle fails rather than
 * recursing until the stack ends.
 */
export function evaluateTable(grid: readonly (readonly string[])[]): (FormulaResult | null)[][] {
  const cached = new Map<string, number | null>();
  const visiting = new Set<string>();
  // The cells whose formulas we are inside, innermost last. `visiting` answers
  // "is this a cycle"; the last entry answers "is this the cell that wrote the
  // range we are expanding", which is a different question with a different
  // answer. See the self-reference note on `range`.
  const chain: string[] = [];

  const textAt = (row: number, col: number): string | undefined => grid[row]?.[col];

  /** The numeric value of one cell, or null when it has none. */
  const valueAt = (row: number, col: number): number | null => {
    const key = `${row}:${col}`;
    if (visiting.has(key)) throw new CycleError();
    const memo = cached.get(key);
    if (memo !== undefined) return memo;
    const text = textAt(row, col);
    if (text === undefined) return null;
    let result: number | null;
    if (isFormulaText(text)) {
      visiting.add(key);
      chain.push(key);
      try {
        result = compute(text, key);
      } finally {
        visiting.delete(key);
        chain.pop();
      }
    } else {
      result = cellNumber(text);
    }
    cached.set(key, result);
    return result;
  };

  /**
   * A single reference used as a number. An empty cell is zero here, the way
   * every spreadsheet reads `=B2-B3` with B3 blank; text has no number and
   * fails the whole formula. Inside a range both are skipped instead, which is
   * the rule that lets a column with a header and a note in it still total.
   */
  const scalar = (row: number, col: number): number => {
    const text = textAt(row, col);
    if (text === undefined) throw new FormulaFailure();
    if (text.trim() === '') return 0;
    const value = valueAt(row, col);
    if (value === null) throw new FormulaFailure();
    return value;
  };

  const range = (a: { row: number; col: number }, b: { row: number; col: number }): number[] => {
    const values: number[] = [];
    // A range skips the cell that wrote it. `=SUM(B2:B99)` in B5, to leave
    // room for rows the user has not added yet, covers B5 itself, and reading
    // that as a cycle would break the most natural way to write a running
    // total. Only the innermost formula is skipped, so a range reaching a
    // DIFFERENT formula that points back still fails as the cycle it is.
    const self = chain[chain.length - 1];
    // Bound the work to cells that exist, even for enormous A1 references.
    const lastRow = Math.min(Math.max(a.row, b.row), grid.length - 1);
    for (let row = Math.max(0, Math.min(a.row, b.row)); row <= lastRow; row++) {
      const lastCol = Math.min(Math.max(a.col, b.col), (grid[row]?.length ?? 0) - 1);
      for (let col = Math.max(0, Math.min(a.col, b.col)); col <= lastCol; col++) {
        if (textAt(row, col) === undefined || `${row}:${col}` === self) continue;
        const value = valueAt(row, col);
        if (value !== null) values.push(value);
      }
    }
    return values;
  };

  const compute = (text: string, cellKey: string): number | null => {
    const tokens = tokenize(text.trim().slice(1));
    if (!tokens || tokens.length === 0) return null;
    let roll = 0;
    const random = () => stableRandom(`${cellKey}|${text}|${roll++}`);
    try {
      const value = new Evaluator(tokens, scalar, range, random).run();
      return Number.isFinite(value) ? value : null;
    } catch (err) {
      if (err instanceof CycleError) throw err;
      return null;
    }
  };

  return grid.map((row, rowIndex) =>
    row.map((text, colIndex) => {
      if (!isFormulaText(text)) return null;
      try {
        const value = valueAt(rowIndex, colIndex);
        return value === null ? { error: true } : { value };
      } catch {
        // A cycle, the one failure that reaches this far.
        return { error: true } as const;
      }
    }),
  );
}

/**
 * How a computed number is shown.
 *
 * Two separate roundings, for two separate problems. The first kills binary
 * floating point, which prints `0.30000000000000004` under a column of `0.1`
 * and `0.2`. The second caps the display at four decimals, because an average
 * of three numbers otherwise fills the cell with a repeating decimal and a
 * budget column stops lining up. Four is past anything money or a unit price
 * needs, and nothing is lost either way: the document keeps the formula, so
 * the exact value is always one click away and nothing rounded is ever
 * written back.
 *
 * Formatting for the reader's language is safe for the same reason.
 */
export function formatFormulaValue(value: number, locale?: string): string {
  const rounded = Number(value.toFixed(10));
  return rounded.toLocaleString(locale, { maximumFractionDigits: 4 });
}
