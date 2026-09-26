// One explicit submission intent per form; transport retry uses the same key.
(() => {
  document.addEventListener('submit', event => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || form.method.toLowerCase() !== 'post') return;
    const path = new URL(form.action, window.location.href).pathname;
    if (!/^\/(clients|connections|settings\/openvpn|networks|network-templates|network\/)/.test(path)) return;
    if (form.querySelector('[name="operation_key"]')) return;
    const field = document.createElement('input');
    field.type = 'hidden';
    field.name = 'operation_key';
    field.value = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');
    form.append(field);
  }, true);
})();
