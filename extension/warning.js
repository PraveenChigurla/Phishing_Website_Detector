const urlParams = new URLSearchParams(window.location.search);
const targetUrl = urlParams.get('url') || 'Unknown';
document.getElementById('target-url').textContent = targetUrl;

document.getElementById('go-back-btn').addEventListener('click', () => {
  // Go back in navigation history
  window.history.go(-2); 
});

document.getElementById('proceed-btn').addEventListener('click', () => {
  // Bypass extension interception (navigate directly)
  window.location.href = targetUrl;
});
