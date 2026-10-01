// JSON API wrapper. 401 flips the shell back to the login view.

import { $ } from './dom.js';

export async function api(path, opts) {
  const r = await fetch(path, opts);
  if (r.status === 401) {
    showLogin();
    throw new Error('unauthorized');
  }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

export function showLogin() {
  $('view-login').style.display = 'block';
  $('view-app').style.display = 'none';
}
