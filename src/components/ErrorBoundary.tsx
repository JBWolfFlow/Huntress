import React, { ReactNode } from 'react';

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: React.ErrorInfo | null;
}

/**
 * ErrorBoundary - Catches React rendering errors and displays recovery UI
 *
 * This class component wraps the application and handles any unhandled
 * React rendering errors, preventing the white screen of death.
 *
 * Features:
 * - Catches rendering errors in child components
 * - Displays user-friendly error message with recovery options
 * - Provides "Try Again" button to reset error state
 * - Provides "Reset Session" button to reload the entire app
 * - Logs full error stack traces to console
 *
 * Usage:
 * ```tsx
 * <ErrorBoundary>
 *   <App />
 * </ErrorBoundary>
 * ```
 */
class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { hasError: true };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo): void {
    // Update state with error details
    this.setState({
      error,
      errorInfo,
    });

    // Log error to console with full stack trace for debugging
    console.error('React Error Boundary caught an error:');
    console.error('Error message:', error.toString());
    console.error('Component stack:', errorInfo.componentStack);
    console.error('Full error object:', error);
    console.error('Full error info:', errorInfo);
  }

  handleTryAgain = (): void => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
    });
  };

  handleResetSession = (): void => {
    // Reload the entire app
    window.location.reload();
  };

  render(): ReactNode {
    if (this.state.hasError) {
      const { error, errorInfo } = this.state;
      const errorMessage = error?.message || 'An unknown error occurred';
      const componentStack = errorInfo?.componentStack || '';

      return (
        <div className="flex items-center justify-center min-h-screen bg-gray-900">
          <div className="w-full max-w-2xl mx-4">
            {/* Error Card */}
            <div className="rounded-lg border border-red-700 bg-gray-800 shadow-2xl overflow-hidden">
              {/* Header */}
              <div className="bg-gradient-to-r from-red-900 to-red-800 px-6 py-4 border-b border-red-700">
                <h1 className="text-2xl font-bold text-red-100 flex items-center gap-3">
                  <svg
                    className="w-6 h-6"
                    fill="currentColor"
                    viewBox="0 0 20 20"
                  >
                    <path
                      fillRule="evenodd"
                      d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                      clipRule="evenodd"
                    />
                  </svg>
                  Something went wrong
                </h1>
              </div>

              {/* Content */}
              <div className="px-6 py-6">
                {/* Error Message */}
                <div className="mb-6">
                  <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wide mb-2">
                    Error Message
                  </h2>
                  <div className="bg-gray-900 rounded border border-gray-700 p-4">
                    <p className="text-gray-100 font-mono text-sm break-words">
                      {errorMessage}
                    </p>
                  </div>
                </div>

                {/* Component Stack (Development/Debug) */}
                {componentStack && (
                  <div className="mb-6">
                    <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wide mb-2">
                      Component Stack
                    </h2>
                    <div className="bg-gray-900 rounded border border-gray-700 p-4 max-h-32 overflow-y-auto">
                      <pre className="text-gray-400 font-mono text-xs whitespace-pre-wrap break-words">
                        {componentStack}
                      </pre>
                    </div>
                  </div>
                )}

                {/* Recovery Information */}
                <div className="mb-6 p-4 bg-blue-900 bg-opacity-30 border border-blue-700 rounded-lg">
                  <p className="text-blue-100 text-sm">
                    The application encountered an unexpected error. Please try one of the recovery options below.
                    If the problem persists, check the browser console for more details.
                  </p>
                </div>
              </div>

              {/* Footer - Action Buttons */}
              <div className="flex gap-3 px-6 py-4 bg-gray-850 border-t border-gray-700">
                <button
                  onClick={this.handleTryAgain}
                  className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white font-medium rounded-lg transition-colors duration-200 flex items-center justify-center gap-2"
                >
                  <svg
                    className="w-4 h-4"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                    />
                  </svg>
                  Try Again
                </button>

                <button
                  onClick={this.handleResetSession}
                  className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 active:bg-red-800 text-white font-medium rounded-lg transition-colors duration-200 flex items-center justify-center gap-2"
                >
                  <svg
                    className="w-4 h-4"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M13 10V3L4 14h7v7l9-11h-7z"
                    />
                  </svg>
                  Reset Session
                </button>
              </div>
            </div>

            {/* Footer Text */}
            <p className="text-center text-gray-500 text-xs mt-6">
              Error ID: {error?.name || 'UNKNOWN'} | Check console for full trace
            </p>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
export { ErrorBoundary };
