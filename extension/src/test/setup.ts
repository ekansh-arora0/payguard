/**
 * Jest test setup file.
 * Provides mocks for browser APIs.
 */

// Mock chrome.storage API
const mockStorage: Record<string, string> = {};

const mockChromeStorage = {
  local: {
    get: jest.fn((keys: string[], callback: (result: Record<string, unknown>) => void) => {
      const result: Record<string, unknown> = {};
      keys.forEach(key => {
        if (mockStorage[key] !== undefined) {
          result[key] = mockStorage[key];
        }
      });
      callback(result);
    }),
    set: jest.fn((items: Record<string, unknown>, callback?: () => void) => {
      Object.entries(items).forEach(([key, value]) => {
        mockStorage[key] = value as string;
      });
      if (callback) callback();
    }),
    remove: jest.fn((keys: string[], callback?: () => void) => {
      keys.forEach(key => {
        delete mockStorage[key];
      });
      if (callback) callback();
    }),
    clear: jest.fn((callback?: () => void) => {
      Object.keys(mockStorage).forEach(key => {
        delete mockStorage[key];
      });
      if (callback) callback();
    })
  }
};

const mockChromeRuntime = {
  lastError: null as { message: string } | null
};

// Set up global chrome mock
(global as any).chrome = {
  storage: mockChromeStorage,
  runtime: mockChromeRuntime
};

// Helper to clear storage between tests
export function clearMockStorage(): void {
  Object.keys(mockStorage).forEach(key => {
    delete mockStorage[key];
  });
}

// Helper to set mock storage values
export function setMockStorage(items: Record<string, string>): void {
  Object.entries(items).forEach(([key, value]) => {
    mockStorage[key] = value;
  });
}

// Helper to get mock storage values
export function getMockStorage(): Record<string, string> {
  return { ...mockStorage };
}

// Reset mocks before each test
beforeEach(() => {
  clearMockStorage();
  jest.clearAllMocks();
  mockChromeRuntime.lastError = null;
});
