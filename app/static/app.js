document.addEventListener("submit", (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  const dangerButton = form.querySelector("button.danger");
  const confirmInput = form.querySelector('input[name="confirm_name"]');
  if (!dangerButton || !confirmInput) return;
  if (!confirmInput.value.trim()) {
    event.preventDefault();
    confirmInput.focus();
  }
});
