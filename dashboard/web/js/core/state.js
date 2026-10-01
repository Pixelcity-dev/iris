// Shared mutable client state. Single object so modules can cooperate
// without import cycles or setter boilerplate.

export const state = {
  me_admin: false,
  currentSec: 'overview',

  // plan / quota
  planDailyResetAt: 0,

  // trend windows
  trendDays: 30,
  adminTrendDays: 30,

  // scans toolbar
  autoTimer: null,

  // plans page
  billingInterval: { pro: 'monthly', enterprise: 'monthly' },

  // admin directory
  adminUsers: [],
  admCur: null,
  adminUserFilter: '',
};
