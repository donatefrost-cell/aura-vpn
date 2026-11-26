// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { M3Slider } from '../components/md3/M3Slider';

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

describe('M3Slider', () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => {
      root.unmount();
    });
    container.remove();
  });

  it('renders accurate progress fill width at 0%, 50%, and 100%', () => {
    const cases = [
      { value: 5, expectedPct: '0.00', expectedWidth: '0%' },
      { value: 17.5, expectedPct: '50.00', expectedWidth: '50%' },
      { value: 30, expectedPct: '100.00', expectedWidth: '100%' },
    ];

    for (const c of cases) {
      act(() => {
        root.render(
          <M3Slider
            min={5}
            max={30}
            step={0.5}
            value={c.value}
            onChange={() => {}}
            ariaLabel="Timeout"
          />,
        );
      });

      const fill = container.querySelector('[data-testid="m3-slider-fill"]') as HTMLElement | null;
      expect(fill).not.toBeNull();
      expect(fill?.dataset.progress).toBe(c.expectedPct);
      expect(fill?.style.width).toBe(c.expectedWidth);
    }
  });

  it('calls onChange and onCommit on input change and keyboard arrow interaction', () => {
    const onChange = vi.fn();
    const onCommit = vi.fn();

    act(() => {
      root.render(
        <M3Slider
          min={5}
          max={30}
          step={1}
          value={12}
          onChange={onChange}
          onCommit={onCommit}
          ariaLabel="Core timeout"
        />,
      );
    });

    const input = container.querySelector('input[type="range"]') as HTMLInputElement;
    expect(input).not.toBeNull();

    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    act(() => {
      setter?.call(input, '20');
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
    });
    expect(onChange).toHaveBeenCalledWith(20);

    act(() => {
      input.dispatchEvent(new KeyboardEvent('keyup', { key: 'ArrowRight', bubbles: true }));
    });
    expect(onCommit).toHaveBeenCalled();
  });

  it('shows formatted value bubble on focus and hides on blur', () => {
    act(() => {
      root.render(
        <M3Slider
          min={90}
          max={120}
          step={5}
          value={105}
          showTicks
          formatValue={(v) => `${v}%`}
          onChange={() => {}}
          ariaLabel="Scale"
        />,
      );
    });

    const input = container.querySelector('input[type="range"]') as HTMLInputElement;
    expect(container.querySelector('[data-testid="m3-slider-bubble"]')).toBeNull();

    act(() => {
      input.dispatchEvent(new FocusEvent('focusin', { bubbles: true }));
      input.dispatchEvent(new FocusEvent('focus', { bubbles: true }));
    });
    const bubble = container.querySelector('[data-testid="m3-slider-bubble"]');
    expect(bubble?.textContent).toBe('105%');

    act(() => {
      input.dispatchEvent(new FocusEvent('focusout', { bubbles: true }));
      input.dispatchEvent(new FocusEvent('blur', { bubbles: true }));
    });
    expect(container.querySelector('[data-testid="m3-slider-bubble"]')).toBeNull();
  });

  it('respects disabled state and suppresses bubble when disabled', () => {
    act(() => {
      root.render(
        <M3Slider
          min={5}
          max={30}
          value={15}
          disabled
          onChange={() => {}}
          ariaLabel="Disabled slider"
        />,
      );
    });

    const input = container.querySelector('input[type="range"]') as HTMLInputElement;
    expect(input.disabled).toBe(true);
    act(() => {
      input.dispatchEvent(new FocusEvent('focusin', { bubbles: true }));
    });
    expect(container.querySelector('[data-testid="m3-slider-bubble"]')).toBeNull();
  });
});
