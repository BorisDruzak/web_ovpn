(() => {
  const form = document.querySelector("[data-inventory-asset-form]") || document.querySelector("[data-inventory-discovery-form]");
  if (!form) return;
  const feedback = form.querySelector("[data-draft-feedback]");
  const identifier = form.elements.namedItem("draft_id").value;
  const csrf = form.elements.namedItem("csrf_token").value;
  const ignored = new Set(["csrf_token", "draft_id", "asset_type", "parent_asset_id", "manual_mode", "location_id", "return_location_id", "save_next"]);
  const fields = () => Object.fromEntries(Array.from(new FormData(form)).filter(([key, value]) => !ignored.has(key) && typeof value === "string"));
  const snapshot = () => JSON.stringify(fields());
  const initial = snapshot();
  let acknowledged = initial;
  let revision = Number(form.dataset.draftRevision);
  let timer = null, running = null, lastStarted = 0, leaving = false, stopped = false;
  const changed = () => form.dataset.restoredDraft === "true" || snapshot() !== initial;
  const schedule = () => {
    clearTimeout(timer);
    if (leaving || stopped || running || document.hidden || snapshot() === acknowledged) return;
    timer = setTimeout(save, Math.max(1500, 5000 - (Date.now() - lastStarted)));
  };
  const save = async () => {
    timer = null;
    if (leaving || stopped || running || document.hidden) return;
    const sent = snapshot();
    if (sent === acknowledged) return;
    const controller = new AbortController();
    running = controller;
    lastStarted = Date.now();
    const timeout = setTimeout(() => controller.abort(), 10000);
    feedback.textContent = "Сохраняю черновик…";
    try {
      const response = await fetch(`/inventory/drafts/${encodeURIComponent(identifier)}`, {
        method:"POST", credentials:"same-origin", signal:controller.signal,
        headers:{"Content-Type":"application/json", "X-CSRF-Token":csrf},
        body:JSON.stringify({fields:JSON.parse(sent), draft_revision:revision}),
      });
      const result = await response.json();
      if (leaving) return;
      if (!response.ok) {
        // No blind retry with a freshly fetched revision: it could overwrite
        // another copy of this same draft. Local input stays visible.
        stopped = true;
        feedback.textContent = response.status === 409
          ? "Черновик изменился в другой вкладке. Ввод здесь сохранён; сравните версии перед продолжением."
          : "Черновик не сохранён. Ввод остался в форме; сохраните карточку или скопируйте его перед уходом.";
        return;
      }
      if (!Number.isInteger(result.draft_revision)) throw new Error("Invalid draft response");
      revision = result.draft_revision;
      acknowledged = sent;
      feedback.textContent = "Черновик сохранён на сервере. Изменения карточки ещё не записаны.";
    } catch (_) {
      if (!leaving) {
        // A lost response has an unknown commit result; automatic retry would
        // reuse an obsolete revision. Preserve input and report uncertainty.
        stopped = true;
        feedback.textContent = "Не удалось подтвердить сохранение черновика. Ввод остался в форме; проверьте восстановление в отдельной вкладке.";
      }
    } finally {
      clearTimeout(timeout);
      running = null;
      schedule();
    }
  };
  form.addEventListener("input", () => {
    feedback.textContent = stopped
      ? "Автосохранение приостановлено. Ввод остался в форме; сохраните карточку или сравните версии черновика."
      : "Есть изменения. Черновик будет сохранён автоматически.";
    schedule();
  });
  form.addEventListener("change", schedule);
  form.addEventListener("submit", (event) => {
    if (event.defaultPrevented) return;
    leaving = true;
    clearTimeout(timer);
    running?.abort();
  });
  document.querySelector("[data-discard-draft]")?.addEventListener("submit", (event) => {
    if (!window.confirm("Отбросить черновик и введённые изменения?")) { event.preventDefault(); return; }
    leaving = true;
    clearTimeout(timer);
    running?.abort();
  });
  window.addEventListener("beforeunload", (event) => {
    if (!leaving && changed()) { event.preventDefault(); event.returnValue = ""; }
  });
  window.addEventListener("pagehide", () => { leaving = true; clearTimeout(timer); running?.abort(); });
  window.addEventListener("pageshow", () => { leaving = false; schedule(); });
  document.addEventListener("visibilitychange", schedule);
})();
