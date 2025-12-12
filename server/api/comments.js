import db from '../db.js';
import { randomUUID } from 'crypto';

function sanitizeContent(content) {
  if (typeof content !== 'string') return '';
  
  return content
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

function validateContent(content) {
  if (!content || typeof content !== 'string') return false;
  if (content.length < 1 || content.length > 10000) return false;
  
  const banned = [
    /\bnigg\w*\b/i,
    /\bcunt\b/i,
    /\bchink\b/i,
    /\bfag\w*\b/i,
    /\btrann\w*\b/i,
    /\bspic\b/i,
    /\bslut\b/i,
    /\bwhore\b/i,
    /\bretard\b/i
  ];
  
  if (banned.some(r => r.test(content))) return false;
  
  const dangerousPatterns = [
    /<script/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /<iframe/i,
    /<object/i,
    /<embed/i,
    /data:text\/html/i
  ];
  
  if (dangerousPatterns.some(p => p.test(content))) return false;
  
  return true;
}

export async function addCommentHandler(req, res) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const { type, targetId, content } = req.body;
  
  if (!['changelog', 'feedback'].includes(type)) {
    return res.status(400).json({ error: 'Invalid type' });
  }
  
  if (!targetId || typeof targetId !== 'string') {
    return res.status(400).json({ error: 'Invalid targetId' });
  }
  
  if (!validateContent(content)) {
    return res.status(400).json({ error: 'Invalid or inappropriate content' });
  }
  
  const sanitizedContent = sanitizeContent(content);
  const id = randomUUID();
  const now = Date.now();
  
  db.prepare('INSERT INTO comments (id, type, target_id, user_id, content, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, type, targetId, req.session.user.id, sanitizedContent, now);
  
  res.json({ message: 'Comment posted.' });
}

export async function getCommentsHandler(req, res) {
  const { type, targetId } = req.query;
  
  if (!['changelog', 'feedback'].includes(type)) {
    return res.status(400).json({ error: 'Invalid type' });
  }
  
  if (!targetId || typeof targetId !== 'string') {
    return res.status(400).json({ error: 'Invalid targetId' });
  }
  
  const comments = db.prepare(
    'SELECT c.*, u.username, u.avatar_url FROM comments c LEFT JOIN users u ON c.user_id = u.id WHERE c.type = ? AND c.target_id = ? ORDER BY c.created_at ASC'
  ).all(type, targetId);
  
  res.json({ comments });
}
