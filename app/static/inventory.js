document.addEventListener("change", (event) => {
  const target = event.target;
  if (target.matches("input[type='file']") && target.files.length) {
    target.setAttribute("data-selected", "true");
  }
});

const inventoryManualForm = document.querySelector("[data-inventory-asset-form]");
const inventoryManualDraft = () => inventoryManualForm
  ? new URLSearchParams(new FormData(inventoryManualForm)).toString() : "";
let inventoryInitialDraft = inventoryManualDraft();
let inventoryFormSubmitting = false;
const endpointFormFields = { ip: "ip_address", mac: "mac_address" };
const endpointInsertUndo = new WeakMap();
const insertionFeedback = (message) => {
  const feedback = inventoryManualForm?.querySelector("[data-inventory-insert-feedback]");
  if (feedback) feedback.textContent = message;
};

const endpointInsertValue = (control, value) => {
  if (!(control instanceof HTMLSelectElement)) return value;
  if (Array.from(control.options).some((option) => option.value === value)) return value;
  const normalized = String(value).toLowerCase();
  if (control.name === "cpu_model") {
    if (normalized.includes("intel")) return "Intel";
    if (normalized.includes("amd")) return "AMD";
  }
  if (control.name === "os_name") {
    if (normalized.includes("windows")) return "Windows";
    if (normalized.includes("linux")) return "Linux";
  }
  if (control.name === "storage_type") {
    if (normalized.includes("m.2") || normalized.includes("nvme")) return "M.2";
    if (normalized.includes("ssd")) return "SSD";
  }
  return null;
};

if (inventoryManualForm) {
  inventoryManualForm.addEventListener("submit", (event) => {
    const card = document.querySelector("[data-endpoint-card]");
    if (card && card.dataset.busy === "true") {
      event.preventDefault();
      card.querySelector("[data-endpoint-feedback]").textContent = "Дождитесь завершения действия агента перед сохранением карточки.";
    } else {
      inventoryFormSubmitting = true;
    }
  });
}

document.addEventListener("click", async (event) => {
  const insert = event.target.closest("[data-endpoint-insert]");
  if (insert && !insert.disabled) {
    const field = endpointFormFields[insert.dataset.endpointInsert] || insert.dataset.endpointInsert;
    const control = inventoryManualForm?.elements.namedItem(field);
    if (!control || !(control instanceof HTMLElement) || !("value" in control)) {
      insertionFeedback("Для этого значения нет подходящего поля формы.");
      return;
    }
    const undo = endpointInsertUndo.get(insert);
    if (undo) {
      if (control.value !== undo.inserted) {
        insertionFeedback("Поле изменено вручную после вставки. Отмена не заменяет новый ввод.");
      } else {
        control.value = undo.previous;
        control.dispatchEvent(new Event("input", { bubbles: true }));
        control.dispatchEvent(new Event("change", { bubbles: true }));
        insertionFeedback("Вставка отменена. Предыдущее значение восстановлено.");
      }
      endpointInsertUndo.delete(insert);
      insert.textContent = "Вставить";
      return;
    }
    const raw = insert.dataset.endpointValue;
    if (raw === undefined || raw === "") {
      insertionFeedback("Источник не содержит значения. Поле не изменено.");
      return;
    }
    const value = endpointInsertValue(control, raw);
    if (value === null) {
      insertionFeedback("Значение источника не поддерживается этим справочником. Поле не изменено.");
      return;
    }
    const previous = control.value;
    if (control.type === "number" && !Number.isFinite(Number(value))) {
      insertionFeedback("Значение источника не подходит формату или диапазону поля. Поле не изменено.");
      return;
    }
    control.value = value;
    if ((control.type === "number" || control.type === "date") && (control.value === "" || !control.checkValidity())) {
      control.value = previous;
      insertionFeedback("Значение источника не подходит формату или диапазону поля. Поле не изменено.");
      return;
    }
    endpointInsertUndo.set(insert, { previous, inserted: control.value });
    control.dispatchEvent(new Event("input", { bubbles: true }));
    control.dispatchEvent(new Event("change", { bubbles: true }));
    insert.textContent = "Отменить вставку";
    insertionFeedback(previous ? "Значение заменено в форме. Можно отменить вставку до сохранения."
      : "Значение вставлено в форму. Для записи нажмите «Сохранить».");
    control.focus();
    return;
  }
  const button = event.target.closest("[data-endpoint-action], [data-endpoint-read]");
  if (!button || button.disabled) return;
  const card = button.closest("[data-endpoint-card]");
  if (!card || card.dataset.busy === "true" || inventoryFormSubmitting) return;
  const feedback = card.querySelector("[data-endpoint-feedback]");
  if (inventoryManualForm?.dataset.restoredDraft === "true" || inventoryManualDraft() !== inventoryInitialDraft) {
    feedback.textContent = "Сохраните изменения карточки перед действием с агентом. Несохранённые поля оставлены в форме.";
    feedback.scrollIntoView({ block: "nearest" });
    return;
  }
  if (button.dataset.confirm && !window.confirm(button.dataset.confirm)) return;
  const read = Boolean(button.dataset.endpointRead);
  const path = button.dataset.endpointRead || button.dataset.endpointAction;
  // Only the local Inventory API can be called by this UI.
  const url = new URL(path, window.location.origin);
  if (url.origin !== window.location.origin || !url.pathname.startsWith("/api/v1/inventory/assets/")) return;
  const controls = Array.from(card.querySelectorAll("button"));
  const formSubmits = inventoryManualForm
    ? Array.from(inventoryManualForm.querySelectorAll("button[type='submit'], input[type='submit']")) : [];
  const submitDisabled = formSubmits.map((control) => control.disabled);
  const draftAtRequest = new URLSearchParams(inventoryManualDraft());
  card.dataset.busy = "true";
  controls.forEach((control) => { control.disabled = true; });
  formSubmits.forEach((control) => { control.disabled = true; });
  feedback.textContent = "Выполняется…";
  try {
    const response = await fetch(url.pathname, {
      method: read ? "GET" : "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": card.dataset.csrf,
        "X-Inventory-Revision": card.dataset.manualRevision },
      body: read ? undefined : JSON.stringify(button.dataset.resolution
        ? { action: button.dataset.resolution, expected_revision: button.dataset.revision } : { profile: "baseline_v1" }),
    });
    const result = await response.json();
    if (response.ok && button.dataset.resolution && inventoryManualForm) {
      const field = result.data.field;
      if (!["ram_gb", "serial_number"].includes(field) || result.data.manual_value === undefined) {
        throw new Error("Missing resolved manual value");
      }
      const input = inventoryManualForm.elements.namedItem(field);
      const manualValue = String(result.data.manual_value ?? "");
      if (input && input.value === draftAtRequest.get(field)) input.value = manualValue;
      const baseline = new URLSearchParams(inventoryInitialDraft);
      baseline.set(field, manualValue);
      inventoryInitialDraft = baseline.toString();
    }
    if (!response.ok) {
      const messages = {
        endpoint_platform_disabled: "Интеграция Endpoint отключена. Сохранённые данные доступны.",
        endpoint_platform_scope_denied: "Недостаточно прав сервиса Endpoint. Обратитесь к администратору.",
        endpoint_platform_unavailable: "Endpoint временно недоступен. Сохранённые данные доступны.",
      };
      feedback.textContent = response.status === 409
        ? "Данные расхождения изменились. Обновите карточку и проверьте новые значения перед решением."
        : messages[result.code] || (response.status === 401
        ? "Сессия завершена. Войдите снова."
        : "Действие не выполнено. Обновите карточку и проверьте актуальность привязки.");
    } else if (response.status === 202) {
      feedback.textContent = "Обновление запрошено. Результат появится после плановой синхронизации; обновите карточку позже.";
    } else if (read && !result.data.length) {
      feedback.textContent = "Сохранённых кандидатов нет. Дождитесь плановой синхронизации и повторите поиск.";
    } else if (inventoryManualDraft() !== inventoryInitialDraft) {
      feedback.textContent = result.manual_revision
        ? "Карточка изменена. Ввод сохранён в черновике; обновите карточку и сравните изменения перед сохранением."
        : "Действие выполнено. Сохраните введённые изменения карточки перед обновлением страницы.";
    } else if (result.manual_revision) {
      const refreshed = new URL(window.location.href);
      refreshed.searchParams.delete("draft_id");
      window.location.assign(refreshed.href);
    } else {
      window.location.reload();
    }
  } catch {
    feedback.textContent = "Не удалось выполнить запрос. Сохранённые данные остаются доступны.";
  } finally {
    card.dataset.busy = "false";
    controls.forEach((control) => { control.disabled = false; });
    formSubmits.forEach((control, index) => { control.disabled = submitDisabled[index]; });
  }
});
