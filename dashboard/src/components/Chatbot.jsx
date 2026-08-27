/**
 * NetShield AI — AI Chatbot panel component.
 *
 * Slide-out panel with chat bubbles for the Gemini-powered security
 * assistant. Includes quick-action buttons and a typing indicator.
 *
 * @module components/Chatbot
 */

import { useState, useRef, useEffect } from 'react'
import { MessageSquare, X, Send, Bot, User } from 'lucide-react'
import { sendChatbotQuery, getChatbotStatus } from '../api/client.js'

const QUICK_ACTIONS = [
  'What attacks happened today?',
  'Is my network safe right now?',
  'What is a DDoS attack?',
  'Show top attacker IPs',
]

export default function Chatbot() {
  const [open, setOpen] = useState(false)
  const [messages, setMessages] = useState([
    {
      role: 'bot',
      text: 'Hello! I am the NetShield AI assistant. Ask me about current threats, attack types, or network security.',
      time: new Date(),
    },
  ])
  const [input, setInput] = useState('')
  const [typing, setTyping] = useState(false)
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

  // Keyboard shortcut: Ctrl+K (or Cmd+K on Mac) toggles the chat panel
  useEffect(() => {
    const handler = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault()
        setOpen(prev => !prev)
      }
      // Escape closes the panel
      if (e.key === 'Escape' && open) {
        setOpen(false)
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
          </div>
          <button className="chat-close" onClick={() => setOpen(false)}>
            <X size={18} />
          </button>
        </div>

        <div className="chat-messages" ref={scrollRef}>
          {messages.map((msg, i) => (
            <div key={i} className={`msg-row ${msg.role === 'user' ? 'msg-row-user' : 'msg-row-bot'}`}>
              <div className={`msg-bubble ${msg.role === 'user' ? 'msg-bubble-user' : 'msg-bubble-bot'}`}>
                {msg.role === 'bot' && <Bot size={14} className="msg-icon" />}
                {msg.role === 'user' && <User size={14} className="msg-icon" />}
                <span className="msg-text">{msg.text}</span>
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
      {open && <div className="chat-backdrop" onClick={() => setOpen(false)} />}

      <style>{`
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

        .chat-backdrop {
          position: fixed;
          inset: 0;
          background: rgba(0,0,0,0.4);
          z-index: 290;
        }

        .chat-panel {
          position: fixed;
          top: 0;
          right: 0;
          width: 380px;
          max-width: 100vw;
          height: 100vh;
          background: var(--bg-secondary);
          border-left: 1px solid var(--border-default);
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

        .chat-panel-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 16px;
          border-bottom: 1px solid var(--border-default);
          flex-shrink: 0;
        }
        .chat-panel-title {
          display: flex;
          align-items: center;
          gap: 8px;
          font-weight: 600;
          font-size: 0.95rem;
        }
        .chat-close {
          background: none;
          border: none;
          color: var(--text-secondary);
          cursor: pointer;
          padding: 4px;
          border-radius: 6px;
          display: flex;
          transition: all 0.2s;
        }
        .chat-close:hover {
          background: var(--bg-hover);
          color: var(--text-primary);
        }

        .chat-messages {
          flex: 1;
          overflow-y: auto;
          padding: 16px;
          display: flex;
          flex-direction: column;
          gap: 12px;
        }
        .msg-row {
          display: flex;
          flex-direction: column;
          gap: 3px;
          max-width: 85%;
        }
        .msg-row-bot { align-self: flex-start; }
        .msg-row-user { align-self: flex-end; }
        .msg-bubble {
          display: flex;
          align-items: flex-start;
          gap: 6px;
          padding: 10px 14px;
          border-radius: 14px;
          font-size: 0.85rem;
          line-height: 1.4;
        }
        .msg-bubble-bot {
          background: var(--bg-tertiary);
          border: 1px solid var(--border-default);
          border-bottom-left-radius: 4px;
        }
        .msg-bubble-user {
          background: rgba(0,240,255,0.12);
          color: var(--text-primary);
          border: 1px solid rgba(0,240,255,0.2);
          border-bottom-right-radius: 4px;
        }
        .msg-icon {
          flex-shrink: 0;
          margin-top: 2px;
          color: var(--text-secondary);
        }
        .msg-time {
          font-size: 0.65rem;
          padding: 0 4px;
        }
        .typing-dot {
          width: 7px;
          height: 7px;
          border-radius: 50%;
          background: var(--text-secondary);
          display: inline-block;
          animation: typing-dot 1.4s infinite;
        }

        .chat-quick-actions {
          display: flex;
          flex-wrap: wrap;
          gap: 6px;
          padding: 8px 16px;
          border-top: 1px solid var(--border-default);
        }
        .quick-btn {
          background: var(--bg-tertiary);
          border: 1px solid var(--border-default);
          border-radius: 14px;
          padding: 4px 10px;
          color: var(--text-secondary);
          font-size: 0.72rem;
          cursor: pointer;
          white-space: nowrap;
          transition: all 0.2s;
        }
        .quick-btn:hover {
          background: var(--bg-hover);
          border-color: var(--accent-cyan);
          color: var(--accent-cyan);
        }
        .quick-btn:disabled {
          opacity: 0.4;
          cursor: not-allowed;
        }

        .chat-input-row {
          display: flex;
          gap: 8px;
          padding: 12px 16px;
          border-top: 1px solid var(--border-default);
          flex-shrink: 0;
        }
        .chat-input {
          flex: 1;
          background: var(--bg-tertiary);
          border: 1px solid var(--border-default);
          border-radius: 8px;
          padding: 10px 14px;
          color: var(--text-primary);
          font-size: 0.85rem;
          outline: none;
          transition: border-color 0.2s;
        }
        .chat-input:focus {
          border-color: var(--accent-cyan);
        }
        .chat-send {
          background: var(--accent-cyan);
          color: var(--bg-primary);
          border: none;
          border-radius: 8px;
          padding: 0 14px;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: opacity 0.2s;
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
