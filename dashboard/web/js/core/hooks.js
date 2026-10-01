// Named hooks let lower layers notify upper layers (and siblings)
// without importing them — used to refresh admin panels after
// user-level deletes and to re-run init() after profile saves.

const hooks = {};

export function hook(name, fn) {
  (hooks[name] ||= []).push(fn);
}

export function fire(name) {
  (hooks[name] || []).slice().forEach(fn => fn());
}
