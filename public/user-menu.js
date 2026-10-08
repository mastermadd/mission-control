(() => {
  const root = document.querySelector('#user-menu');
  const toggle = document.querySelector('#user-toggle');
  const actions = document.querySelector('#user-actions');
  const signOut = document.querySelector('#sign-out');
  function setOpen(open) {
    actions.hidden = !open;
    toggle.setAttribute('aria-expanded', String(open));
  }
  toggle.addEventListener('click', () => setOpen(actions.hidden));
  document.addEventListener('click', event => {
    if (!root.contains(event.target)) setOpen(false);
  });
  root.addEventListener('focusout', event => {
    if (!root.contains(event.relatedTarget)) setOpen(false);
  });
  root.addEventListener('keydown', event => {
    if (event.key === 'Escape' && !actions.hidden) {
      event.preventDefault();
      setOpen(false);
      toggle.focus();
    }
  });
  document.querySelector('#import-workspace').addEventListener('click', () => {
    setOpen(false);
    migrationDialog();
  });
  signOut.addEventListener('click', async () => {
    setOpen(false);
    signOut.disabled = true;
    try {
      const response = await fetch('/auth/logout', {method: 'POST'});
      if (!response.ok && response.status !== 401) throw Error('Sign out failed. Please try again.');
      location.href = '/login';
    } catch (error) {
      toast(error.message);
    } finally {
      signOut.disabled = false;
    }
  });
})();
