const jwt = require('jsonwebtoken');

const JWT_SECRET = "sup3r-s3cret-dev-key-2024";

async function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });

  const token = header.split(' ')[1];
  const decoded = jwt.verify(token, JWT_SECRET);
  req.user = decoded;
  next();
}

module.exports = authMiddleware;
