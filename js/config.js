// Signup Worker endpoint. An empty string hides the form and shows "Signups open soon".
export const SIGNUP_URL = 'https://toolkit-signup.starswarm.workers.dev/api/signup';

// Public Turnstile site key. Empty means the page does not load the Turnstile script.
export const TURNSTILE_SITE_KEY = '';

export function shouldShowSignupForm(url = SIGNUP_URL) {
  return Boolean(String(url || '').trim());
}

export function shouldLoadTurnstile(url = SIGNUP_URL, siteKey = TURNSTILE_SITE_KEY) {
  return shouldShowSignupForm(url) && Boolean(String(siteKey || '').trim());
}
