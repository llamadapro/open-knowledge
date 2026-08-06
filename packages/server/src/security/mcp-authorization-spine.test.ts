import { describe, expect, test, vi } from 'vitest';
import { createLoggedServer } from '../mcp/tool-logging.ts';

describe('MCP authorization registration spine', () => {
  test('passes tool arguments to the gate before invoking the handler', async () => {
    let capturedHandler: ((...args: unknown[]) => unknown) | undefined;
    const fakeServer = {
      registerTool: (_name: string, _config: unknown, handler: (...args: unknown[]) => unknown) => {
        capturedHandler = handler;
      },
      tool: vi.fn(),
    };
    const authorizeToolCall = vi.fn(async () => undefined);
    const originalHandler = vi.fn(async () => ({ content: [] }));
    const wrapped = createLoggedServer(fakeServer as never, { authorizeToolCall });

    wrapped.registerTool('lint', {}, originalHandler);
    const args = { document: 'handbook', fix: true };
    await capturedHandler?.(args);

    expect(authorizeToolCall).toHaveBeenCalledWith('lint', args);
    expect(originalHandler).toHaveBeenCalledWith(args);
    expect(authorizeToolCall.mock.invocationCallOrder[0]).toBeLessThan(
      originalHandler.mock.invocationCallOrder[0] ?? Number.POSITIVE_INFINITY,
    );
  });

  test('fails closed without invoking the tool when authorization rejects', async () => {
    let capturedHandler: ((...args: unknown[]) => unknown) | undefined;
    const fakeServer = {
      registerTool: (_name: string, _config: unknown, handler: (...args: unknown[]) => unknown) => {
        capturedHandler = handler;
      },
      tool: vi.fn(),
    };
    const originalHandler = vi.fn();
    const wrapped = createLoggedServer(fakeServer as never, {
      authorizeToolCall: async () => {
        throw new Error('denied');
      },
    });

    wrapped.registerTool('write', {}, originalHandler);
    await expect(capturedHandler?.({ document: { path: 'handbook' } })).rejects.toThrow('denied');
    expect(originalHandler).not.toHaveBeenCalled();
  });
});
