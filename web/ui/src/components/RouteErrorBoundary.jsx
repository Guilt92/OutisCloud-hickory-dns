import React from 'react';

export default class RouteErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { failed: false };
  }

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch(error) {
    // Keep error details out of the customer-facing page.
    console.error('Unable to render the current page', error);
  }

  render() {
    if (this.state.failed) {
      return (
        <main className="mx-auto max-w-xl px-4 py-16" role="alert">
          <h1 className="font-display text-2xl font-semibold text-ink">This page could not load</h1>
          <p className="mt-3 text-muted">Please try again. If you were saving a change, check its status before retrying.</p>
          <div className="mt-6 flex flex-wrap gap-3">
            <button type="button" className="btn-primary" onClick={() => window.location.reload()}>Retry</button>
            <a className="btn-secondary" href="/">Go to dashboard</a>
          </div>
        </main>
      );
    }
    return this.props.children;
  }
}
