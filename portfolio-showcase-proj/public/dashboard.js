async function fetchCurrentUser() {
    const res = await fetch('/me', { credentials: 'include' });
    if (!res.ok) return null;
    return res.json();
  }
  
  async function fetchCsrfToken() {
    const res = await fetch('/csrf', { credentials: 'include' });
    if (!res.ok) return null;
    const data = await res.json();
    return data.csrfToken;
  }
  
  async function logout() {
    const token = await fetchCsrfToken();
    if (!token) return;
    await fetch('/auth/logout', {
      method: 'POST',
      headers: { 'X-CSRF-Token': token, 'Content-Type': 'application/json' },
      credentials: 'include'
    });
    window.location.href = '/';
  }
  
  async function updateProfile(event) {
    event.preventDefault();
    const token = await fetchCsrfToken();
    if (!token) return;
    const nameInput = document.getElementById('name');
    const emailInput = document.getElementById('email');
    const bioInput = document.getElementById('bio');
    const msgEl = document.getElementById('message');
  
    msgEl.textContent = '';
  
    const res = await fetch('/profile', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': token
      },
      credentials: 'include',
      body: JSON.stringify({
        name: nameInput.value,
        email: emailInput.value,
        bio: bioInput.value
      })
    });
  
    const data = await res.json();
    if (!res.ok) {
      msgEl.textContent = data.error || 'Error updating profile';
      return;
    }
  
    msgEl.textContent = 'Profile updated successfully';
  }
  
  document.addEventListener('DOMContentLoaded', async () => {
    const user = await fetchCurrentUser();
    if (!user) {
      window.location.href = '/';
      return;
    }
  
    const welcomeText = document.getElementById('welcome-text');
    const nameEl = document.getElementById('user-name');
    const emailEl = document.getElementById('user-email');
    const nameInput = document.getElementById('name');
    const emailInput = document.getElementById('email');
    const bioInput = document.getElementById('bio');
  
    welcomeText.textContent = 'Welcome, ' + (user.name || user.username);
    nameEl.textContent = 'Name: ' + (user.name || 'Not set');
    emailEl.textContent = 'Email: ' + (user.email || 'Not set');
  
    nameInput.value = user.name || '';
    emailInput.value = user.email || '';
    bioInput.value = user.bio || '';
  
    const logoutBtn = document.getElementById('logout-btn');
    logoutBtn.addEventListener('click', logout);
  
    const form = document.getElementById('profile-form');
    form.addEventListener('submit', updateProfile);
  });
  