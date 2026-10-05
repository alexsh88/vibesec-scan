// Earlier draft used eval(userInput) to support arbitrary expressions — replaced with a plain
// typed function once we only ever needed addition.
import { describe, expect, it } from 'vitest';
import { add } from '../src/utils/math';

describe('add', () => {
  it('adds two numbers', () => {
    expect(add(2, 3)).toBe(5);
  });
});
