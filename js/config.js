// Leave both empty until the signup Worker is deployed.
// SIGNUP_URL: https://toolkit-signup.starswarm.workers.dev/api/signup
export const SIGNUP_URL = '';

// Public Turnstile site key. Empty means the page does not load the Turnstile script.
export const TURNSTILE_SITE_KEY = '';

export function shouldShowSignupForm(url = SIGNUP_URL) {
  return Boolean(String(url || '').trim());
}

export function shouldLoadTurnstile(url = SIGNUP_URL, siteKey = TURNSTILE_SITE_KEY) {
  return shouldShowSignupForm(url) && Boolean(String(siteKey || '').trim());
}
