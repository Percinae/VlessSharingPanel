document.querySelectorAll('[data-copy]').forEach(button => {
  button.addEventListener('click', async () => {
    const field = document.getElementById(button.dataset.copy);
    try {
      await navigator.clipboard.writeText(field.value);
      button.textContent = 'Скопировано';
    } catch {
      field.select();
      button.textContent = 'Выделено — скопируйте вручную';
    }
  });
});
document.querySelectorAll('form[data-confirm]').forEach(form => {
  form.addEventListener('submit', event => {
    if (!window.confirm(form.dataset.confirm)) event.preventDefault();
  });
});
