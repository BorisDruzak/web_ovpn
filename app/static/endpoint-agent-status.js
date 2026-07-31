(() => {
  let attempts = 0;
  const poll = async () => {
    attempts += 1;
    try {
      const response = await fetch('/network/endpoint-agent-status', { credentials: 'same-origin' });
      if (response.ok && (await response.json()).state !== 'updating') {
        window.location.reload();
        return;
      }
    } catch (_) {
      // The current page remains usable; no error body is logged or rendered.
    }
    if (attempts < 40) window.setTimeout(poll, 3000);
  };
  window.setTimeout(poll, 3000);
})();
