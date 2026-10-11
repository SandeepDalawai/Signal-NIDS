document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.flash-close').forEach(button => button.addEventListener('click', () => button.closest('.flash')?.remove()));
  const input = document.getElementById('traffic-file');
  const name = document.getElementById('file-name');
  const submit = document.getElementById('upload-submit');
  const zone = document.getElementById('upload-zone');
  if (input && name && submit) {
    const setFile = file => {
      if (!file) { name.textContent = 'No file selected'; submit.disabled = true; return; }
      name.textContent = file.name;
      const valid = file.name.toLowerCase().endsWith('.csv') && file.size <= 5 * 1024 * 1024;
      submit.disabled = !valid;
      if (!valid) name.textContent = file.name + (file.size > 5 * 1024 * 1024 ? ' — exceeds 5 MB' : ' — CSV only');
    };
    input.addEventListener('change', () => setFile(input.files?.[0]));
    if (zone) {
      zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('dragover'); });
      zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
      zone.addEventListener('drop', e => {
        e.preventDefault(); zone.classList.remove('dragover');
        const file = e.dataTransfer?.files?.[0];
        if (file) {
          try { const transfer = new DataTransfer(); transfer.items.add(file); input.files = transfer.files; } catch (_) { /* Browser may restrict assigning FileList; user can choose the file instead. */ }
          setFile(file);
        }
      });
      zone.addEventListener('click', e => { if (!e.target.closest('label')) input.click(); });
    }
  }
});
