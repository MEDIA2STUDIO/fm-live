const activeSessions = new Map();

function isSessionAlive(userId) {
  return activeSessions.has(userId);
}

function setSession(userId, token) {
  activeSessions.set(userId, token);
}

function removeSession(userId) {
  activeSessions.delete(userId);
}

module.exports = { isSessionAlive, setSession, removeSession };
