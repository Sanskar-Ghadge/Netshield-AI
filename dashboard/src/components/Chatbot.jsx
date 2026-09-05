/**
 * NetShield AI — AI Chatbot panel component.
 *
 * Slide-out panel with chat bubbles for the Gemini-powered security
 * assistant. Bot messages are rendered as Markdown with proper
 * formatting (bold, lists, headers, spacing). Includes quick-action
 * buttons and a typing indicator.
 *
 * @module components/Chatbot
 */

import { useState, useRef, useEffect, useMemo } from 'react'
import { MessageSquare, X, Send, Bot, User, AlertTriangle, Shield, Activity, Search } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import { sendChatbotQuery, getChatbotStatus } from '../api/client.js'

const QUICK_ACTIONS = [
  'What attacks happened today?',
  'Is my network safe right now?',
  'What is a DDoS attack?',
  'Show top attacker IPs',
]

/**
 * Lightweight Markdown renderer for bot messages.
 * Applies proper formatting: bold for key info, styled lists,
 * proper spacing, and code formatting.
 */
function BotMessage({ content }) {
  return (
    <div className="bot-md">
      <ReactMarkdown
        components={{
          // Bold text → cyan accent color + bold weight
          strong: ({ children }) => (
            <strong className="md-bold">{children}</strong>
          ),
          // Headers → smaller, accent-colored
          h1: ({ children }) => <h1 className="md-h">{children}</h1>,
          h2: ({ children }) => <h2 className="md-h">{children}</h2>,
          h3: ({ children }) => <h3 className="md-h">{children}</h3>,
          // Unordered lists → styled with custom bullets
          ul: ({ children }) => <ul className="md-ul">{children}</ul>,
          li: ({ children }) => <li className="md-li">{children}</li>,
          // Ordered lists
          ol: ({ children }) => <ol className="md-ol">{children}</ol>,
          // Paragraphs → proper spacing
          p: ({ children }) => <p className="md-p">{children}</p>,
          // Inline code
          code: ({ children }) => <code className="md-code">{children}</code>,
          // Block code
          pre: ({ children }) => <pre className="md-pre">{children}</pre>,
          // Links
          a: ({ href, children }) => (
            <a className="md-link" href={href} target="_blank" rel="noopener noreferrer">
              {children}
            </a>
          ),
          // Horizontal rules
          hr: () => <hr className="md-hr" />,
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  )
}

export default function Chatbot({ externalOpen = false, onExternalClose }) {
  const [open, setOpen] = useState(false)

  useEffect(() => {
    if (externalOpen) {
      setOpen(true)
    }
  }, [externalOpen])

  const handleClose = () => {
    setOpen(false)
    if (onExternalClose) onExternalClose()
  }
  const [messages, setMessages] = useState([
    {
      role: 'bot',
      text: 'Hello! I am the **NetShield AI** assistant. Ask me about current threats, attack types, or network security.',
      time: new Date(),
    },
  ])
  const [input, setInput] = useState('')
  const [typing, setTyping] = useState(false)
  const [botStatus, setBotStatus] = useState({ available: true, model: '' })
  const scrollRef = useRef(null)
  const inputRef = useRef(null)

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [messages, typing])

  // Focus input when panel opens
  useEffect(() => {
    if (open && inputRef.current) {
      inputRef.current.focus()
    }
  }, [open])

  // Fetch chatbot status on open
  useEffect(() => {
    if (!open) return
    getChatbotStatus()
      .then((data) => setBotStatus(data))
      .catch(() => setBotStatus({ available: false, model: '' }))
  }, [open])

  // Keyboard shortcut: Ctrl+K (or Cmd+K on Mac) toggles the chat panel
  useEffect(() => {
    const handler = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault()
        setOpen(prev => !prev)
      }
      // Escape closes the panel
      if (e.key === 'Escape' && open) {
        handleClose()
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [open])

  const send = async (text) => {
    const query = text || input.trim()
    if (!query) return

    setInput('')
    setMessages(prev => [...prev, { role: 'user', text: query, time: new Date() }])
    setTyping(true)

    try {
      const response = await sendChatbotQuery(query)
      setMessages(prev => [...prev, { role: 'bot', text: response, time: new Date() }])
    } catch {
      setMessages(prev => [...prev, {
        role: 'bot',
        text: 'Sorry, I could not connect to the server. Please ensure the backend is running.',
        time: new Date(),
      }])
    } finally {
      setTyping(false)
    }
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      send()
    }
  }

  const formatMsgTime = (date) =>
    date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' })

  return (
    <>
      {/* Floating button */}
      <button
        className={`chat-fab ${open ? 'chat-fab-hidden' : ''}`}
        onClick={() => setOpen(true)}
        aria-label="Open chatbot (Ctrl+K)"
        title="Open chatbot (Ctrl+K)"
      >
        <MessageSquare size={24} />
        <span className="chat-fab-pulse" />
        <span className="chat-fab-hint">⌘K</span>
      </button>

      {/* Panel */}
      <div className={`chat-panel ${open ? 'chat-panel-open' : ''}`}>
        <div className="chat-panel-header">
          <div className="chat-panel-title">
            <Bot size={18} style={{ color: 'var(--accent-cyan)' }} />
            <span>NetShield Assistant</span>
            {botStatus.available && botStatus.model && (
              <span className="model-badge">{botStatus.model.replace('models/', '')}</span>
            )}
          </div>
          <button className="chat-close" onClick={handleClose}>
            <X size={18} />
          </button>
        </div>

        <div className="chat-messages" ref={scrollRef}>
          {messages.map((msg, i) => (
            <div key={i} className={`msg-row ${msg.role === 'user' ? 'msg-row-user' : 'msg-row-bot'}`}>
              <div className={`msg-bubble ${msg.role === 'user' ? 'msg-bubble-user' : 'msg-bubble-bot'}`}>
                {msg.role === 'bot' && <Bot size={14} className="msg-icon" />}
                {msg.role === 'user' && <User size={14} className="msg-icon" />}
                {msg.role === 'bot' ? (
                  <BotMessage content={msg.text} />
                ) : (
                  <span className="msg-text">{msg.text}</span>
                )}
              </div>
              <span className="msg-time text-faint mono">{formatMsgTime(msg.time)}</span>
            </div>
          ))}

          {typing && (
            <div className="msg-row msg-row-bot">
              <div className="msg-bubble msg-bubble-bot">
                <span className="typing-dot" style={{ animationDelay: '0s' }} />
                <span className="typing-dot" style={{ animationDelay: '0.2s' }} />
                <span className="typing-dot" style={{ animationDelay: '0.4s' }} />
              </div>
            </div>
          )}
        </div>

        <div className="chat-quick-actions">
          {QUICK_ACTIONS.map((q) => (
            <button key={q} className="quick-btn" onClick={() => send(q)} disabled={typing}>
              {q}
            </button>
          ))}
        </div>

        <div className="chat-input-row">
          <input
            ref={inputRef}
            type="text"
            className="chat-input"
            placeholder="Ask about threats, attacks, or security…"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={typing}
          />
          <button className="chat-send" onClick={() => send()} disabled={typing || !input.trim()}>
            <Send size={16} />
          </button>
        </div>
      </div>

      {/* Backdrop */}
      {open && <div className="chat-backdrop" onClick={handleClose} />}

      <style>{`
        /* ── FAB button ── */
        .chat-fab {
          position: fixed;
          bottom: 24px;
          right: 24px;
          width: 56px;
          height: 56px;
          border-radius: 50%;
          background: var(--accent-cyan);
          color: var(--bg-primary);
          border: none;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 200;
          box-shadow: 0 4px 20px rgba(0,240,255,0.3);
          transition: transform 0.3s, opacity 0.3s;
        }
        .chat-fab:hover {
          transform: scale(1.05);
        }
        .chat-fab-hidden {
          opacity: 0;
          pointer-events: none;
          transform: scale(0.8);
        }
        .chat-fab-pulse {
          position: absolute;
          inset: -4px;
          border-radius: 50%;
          border: 2px solid var(--accent-cyan);
          opacity: 0;
          animation: fab-pulse 2.5s infinite;
        }
        .chat-fab-hint {
          position: absolute;
          right: -2px;
          bottom: -4px;
          background: var(--bg-primary);
          border: 1px solid var(--border-default);
          border-radius: 4px;
          padding: 1px 4px;
          font-size: 0.55rem;
          font-weight: 700;
          color: var(--text-secondary);
          letter-spacing: 0.5px;
        }
        @keyframes fab-pulse {
          0% { opacity: 0.6; transform: scale(1); }
          100% { opacity: 0; transform: scale(1.4); }
        }

        /* ── Backdrop ── */
        .chat-backdrop {
          position: fixed;
          inset: 0;
          background: rgba(0, 0, 0, 0.65);
          backdrop-filter: blur(4px);
          z-index: 290;
        }

        /* ── Panel ── */
        .chat-panel {
          position: fixed;
          top: 0;
          right: 0;
          width: 420px;
          max-width: 100vw;
          height: 100vh;
          background: #090e1a;
          border-left: 1px solid rgba(56, 189, 248, 0.25);
          box-shadow: -10px 0 30px rgba(0, 0, 0, 0.8);
          display: flex;
          flex-direction: column;
          z-index: 300;
          transform: translateX(100%);
          transition: transform 0.3s ease;
        }
        .chat-panel-open {
          transform: translateX(0);
          animation: slide-in-right 0.3s ease;
        }

        /* ── Header ── */
        .chat-panel-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 16px 20px;
          border-bottom: 1px solid rgba(56, 189, 248, 0.2);
          flex-shrink: 0;
          background: #0f172a;
        }
        .chat-panel-title {
          display: flex;
          align-items: center;
          gap: 8px;
          font-family: var(--font-heading);
          font-weight: 700;
          font-size: 1rem;
          color: #f8fafc;
        }
        .model-badge {
          font-size: 0.62rem;
          font-weight: 600;
          padding: 2px 8px;
          border-radius: 10px;
          background: rgba(0, 240, 255, 0.15);
          border: 1px solid rgba(0, 240, 255, 0.3);
          color: var(--accent-cyan);
          letter-spacing: 0.3px;
        }
        .chat-close {
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid rgba(255, 255, 255, 0.1);
          color: var(--text-secondary);
          cursor: pointer;
          padding: 6px;
          border-radius: 8px;
          display: flex;
          transition: all 0.2s;
        }
        .chat-close:hover {
          background: rgba(255, 42, 95, 0.2);
          color: #ff2a5f;
          border-color: rgba(255, 42, 95, 0.4);
        }

        /* ── Messages area ── */
        .chat-messages {
          flex: 1;
          overflow-y: auto;
          padding: 18px;
          display: flex;
          flex-direction: column;
          gap: 14px;
          background: #090e1a;
        }
        .msg-row {
          display: flex;
          flex-direction: column;
          gap: 4px;
          max-width: 90%;
        }
        .msg-row-bot { align-self: flex-start; }
        .msg-row-user { align-self: flex-end; }
        .msg-bubble {
          display: flex;
          align-items: flex-start;
          gap: 8px;
          padding: 12px 16px;
          border-radius: 14px;
          font-size: 0.88rem;
          line-height: 1.55;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }
        .msg-bubble-bot {
          background: #142036;
          border: 1px solid rgba(56, 189, 248, 0.25);
          color: #f8fafc;
          border-bottom-left-radius: 4px;
        }
        .msg-bubble-user {
          background: linear-gradient(135deg, rgba(0, 240, 255, 0.25), rgba(56, 189, 248, 0.15));
          color: #ffffff;
          border: 1px solid rgba(0, 240, 255, 0.4);
          border-bottom-right-radius: 4px;
        }
        .msg-icon {
          flex-shrink: 0;
          margin-top: 3px;
          color: var(--accent-cyan);
        }
        .msg-time {
          font-size: 0.65rem;
          padding: 0 4px;
          color: #64748b;
        }
        .typing-dot {
          width: 7px;
          height: 7px;
          border-radius: 50%;
          background: var(--text-secondary);
          display: inline-block;
          animation: typing-dot 1.4s infinite;
        }

        /* ── Markdown styles for bot messages ── */
        .bot-md {
          overflow-wrap: break-word;
          word-break: break-word;
        }

        /* Bold — accent cyan + heavier weight */
        .md-bold {
          color: var(--accent-cyan);
          font-weight: 700;
        }

        /* Headers */
        .md-h {
          color: var(--accent-cyan);
          font-weight: 700;
          margin: 10px 0 6px 0;
          line-height: 1.3;
        }
        .bot-md h1 { font-size: 1.05rem; }
        .bot-md h2 { font-size: 0.95rem; }
        .bot-md h3 { font-size: 0.88rem; }
        .bot-md h1:first-child,
        .bot-md h2:first-child,
        .bot-md h3:first-child {
          margin-top: 0;
        }

        /* Paragraphs */
        .md-p {
          margin: 6px 0;
          line-height: 1.55;
        }
        .md-p:first-child {
          margin-top: 0;
        }
        .md-p:last-child {
          margin-bottom: 0;
        }

        /* Unordered lists */
        .md-ul {
          margin: 6px 0;
          padding-left: 18px;
          list-style: none;
        }
        .md-li {
          margin: 4px 0;
          padding-left: 4px;
          line-height: 1.5;
          position: relative;
        }
        .md-ul .md-li::before {
          content: '▸';
          position: absolute;
          left: -14px;
          color: var(--accent-cyan);
          font-size: 0.7rem;
          top: 3px;
        }

        /* Ordered lists */
        .md-ol {
          margin: 6px 0;
          padding-left: 20px;
          counter-reset: md-ol-counter;
          list-style: none;
        }
        .md-ol .md-li {
          counter-increment: md-ol-counter;
        }
        .md-ol .md-li::before {
          content: counter(md-ol-counter) '.';
          position: absolute;
          left: -18px;
          color: var(--accent-cyan);
          font-weight: 600;
          font-size: 0.8rem;
          top: 2px;
        }

        /* Inline code */
        .md-code {
          background: rgba(0,240,255,0.08);
          border: 1px solid rgba(0,240,255,0.15);
          border-radius: 4px;
          padding: 1px 5px;
          font-size: 0.8rem;
          font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
          color: var(--accent-cyan);
        }

        /* Block code */
        .md-pre {
          background: rgba(0,0,0,0.3);
          border: 1px solid var(--border-default);
          border-radius: 6px;
          padding: 10px 12px;
          margin: 8px 0;
          overflow-x: auto;
          font-size: 0.78rem;
          line-height: 1.4;
        }
        .md-pre code {
          background: none;
          border: none;
          padding: 0;
          font-size: inherit;
          color: var(--text-primary);
        }

        /* Links */
        .md-link {
          color: var(--accent-cyan);
          text-decoration: underline;
          text-underline-offset: 2px;
        }
        .md-link:hover {
          opacity: 0.85;
        }

        /* Horizontal rule */
        .md-hr {
          border: none;
          border-top: 1px solid var(--border-default);
          margin: 10px 0;
        }

        /* ── Quick actions ── */
        .chat-quick-actions {
          display: flex;
          flex-wrap: wrap;
          gap: 6px;
          padding: 10px 16px;
          border-top: 1px solid rgba(56, 189, 248, 0.2);
          background: #0f172a;
        }
        .quick-btn {
          background: #1e293b;
          border: 1px solid rgba(56, 189, 248, 0.25);
          border-radius: 14px;
          padding: 5px 12px;
          color: #cbd5e1;
          font-size: 0.75rem;
          font-weight: 500;
          cursor: pointer;
          white-space: nowrap;
          transition: all 0.2s;
        }
        .quick-btn:hover {
          background: #334155;
          border-color: var(--accent-cyan);
          color: var(--accent-cyan);
          box-shadow: 0 2px 8px rgba(0, 240, 255, 0.15);
        }
        .quick-btn:disabled {
          opacity: 0.4;
          cursor: not-allowed;
        }

        /* ── Input row ── */
        .chat-input-row {
          display: flex;
          gap: 8px;
          padding: 12px 16px;
          border-top: 1px solid rgba(56, 189, 248, 0.2);
          background: #0f172a;
          flex-shrink: 0;
        }
        .chat-input {
          flex: 1;
          background: #1e293b;
          border: 1px solid rgba(56, 189, 248, 0.3);
          border-radius: 8px;
          padding: 10px 14px;
          color: #f8fafc;
          font-size: 0.88rem;
          outline: none;
          transition: border-color 0.2s, box-shadow 0.2s;
        }
        .chat-input::placeholder {
          color: #64748b;
        }
        .chat-input:focus {
          border-color: var(--accent-cyan);
          box-shadow: 0 0 10px rgba(0, 240, 255, 0.25);
        }
        .chat-send {
          background: var(--accent-cyan);
          color: #060913;
          font-weight: 700;
          border: none;
          border-radius: 8px;
          padding: 0 14px;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: opacity 0.2s, transform 0.1s;
        }
        .chat-send:hover:not(:disabled) {
          transform: scale(1.03);
        }
        .chat-send:disabled {
          opacity: 0.4;
          cursor: not-allowed;
        }

        @media (max-width: 480px) {
          .chat-panel { width: 100vw; }
        }
      `}</style>
    </>
  )
}
