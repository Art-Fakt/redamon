import { useCallback, useRef, KeyboardEvent } from 'react'
import type { ApprovalRequestPayload, QuestionRequestPayload, ToolConfirmationRequestPayload } from '@/lib/websocket-types'
import type { ChatItem, Message } from '../types'

interface ChatSkillSummary {
  id: string
  name: string
  description: string | null
  category: string
  createdAt: string
}

interface ChatSkillFull extends ChatSkillSummary {
  content: string
}

export interface ActiveSkill {
  id: string
  name: string
  category: string
  content: string
}

interface SendHandlersDeps {
  // Chat state
  inputValue: string
  setInputValue: (v: string) => void
  isLoading: boolean
  setIsLoading: (v: boolean) => void
  setIsStopped: (v: boolean) => void
  setIsStopping: (v: boolean) => void
  setChatItems: React.Dispatch<React.SetStateAction<ChatItem[]>>
  chatItems: ChatItem[]
  // Active skill (persistent)
  activeSkill: ActiveSkill | null
  setActiveSkill: (v: ActiveSkill | null) => void
  // Interaction state
  awaitingApproval: boolean
  setAwaitingApproval: (v: boolean) => void
  setApprovalRequest: (v: ApprovalRequestPayload | null) => void
  modificationText: string
  setModificationText: (v: string) => void
  awaitingQuestion: boolean
  setAwaitingQuestion: (v: boolean) => void
  questionRequest: QuestionRequestPayload | null
  setQuestionRequest: (v: QuestionRequestPayload | null) => void
  answerText: string
  setAnswerText: (v: string) => void
  selectedOptions: string[]
  setSelectedOptions: (v: string[]) => void
  awaitingToolConfirmation: boolean
  setAwaitingToolConfirmation: (v: boolean) => void
  setToolConfirmationRequest: (v: ToolConfirmationRequestPayload | null) => void
  // Refs
  isProcessingApproval: React.MutableRefObject<boolean>
  awaitingApprovalRef: React.MutableRefObject<boolean>
  isProcessingQuestion: React.MutableRefObject<boolean>
  awaitingQuestionRef: React.MutableRefObject<boolean>
  isProcessingToolConfirmation: React.MutableRefObject<boolean>
  awaitingToolConfirmationRef: React.MutableRefObject<boolean>
  pendingApprovalToolId: React.MutableRefObject<string | null>
  pendingApprovalWaveId: React.MutableRefObject<string | null>
  // WebSocket senders
  sendQuery: (q: string) => void
  sendGuidance: (m: string) => void
  sendSkillInject: (payload: { skill_id: string; skill_name: string; content: string }) => void
  sendApproval: (decision: 'approve' | 'modify' | 'abort', modification?: string) => void
  sendToolConfirmation: (decision: 'approve' | 'modify' | 'reject', modifications?: Record<string, any>) => void
  sendAnswer: (answer: string) => void
  sendStop: () => void
  sendResume: () => void
  // Conversation
  conversationId: string | null
  setConversationId: (v: string | null) => void
  projectId: string
  userId: string
  sessionId: string
  createConversation: (sessionId: string) => Promise<any>
  saveMessage: (type: string, data: any) => void
  updateConvMeta: (updates: Record<string, any>) => Promise<void>
}

export function useSendHandlers(deps: SendHandlersDeps) {
  const {
    inputValue, setInputValue,
    isLoading, setIsLoading, setIsStopped, setIsStopping,
    setChatItems, chatItems,
    activeSkill, setActiveSkill,
    awaitingApproval, setAwaitingApproval, setApprovalRequest, modificationText, setModificationText,
    awaitingQuestion, setAwaitingQuestion, questionRequest, setQuestionRequest,
    answerText, setAnswerText, selectedOptions, setSelectedOptions,
    awaitingToolConfirmation, setAwaitingToolConfirmation, setToolConfirmationRequest,
    isProcessingApproval, awaitingApprovalRef,
    isProcessingQuestion, awaitingQuestionRef,
    isProcessingToolConfirmation, awaitingToolConfirmationRef,
    pendingApprovalToolId, pendingApprovalWaveId,
    sendQuery, sendGuidance, sendSkillInject, sendApproval, sendToolConfirmation, sendAnswer, sendStop, sendResume,
    conversationId, setConversationId, projectId, userId, sessionId,
    createConversation, saveMessage, updateConvMeta,
  } = deps

  const inputRef = useRef<HTMLTextAreaElement>(null)

  // Helper: add a system-style message to the chat
  const addSystemMessage = useCallback((content: string) => {
    const msg: Message = {
      type: 'message',
      id: `system-${Date.now()}`,
      role: 'assistant',
      content,
      timestamp: new Date(),
    }
    setChatItems(prev => [...prev, msg])
  }, [setChatItems])

  // Activate a skill by its full data (used by both /skill command and picker)
  const activateSkill = useCallback(async (skillId: string, skillName?: string): Promise<ChatSkillFull | null> => {
    let fullSkill: ChatSkillFull
    try {
      const res = await fetch(`/api/users/${userId}/chat-skills/${skillId}`)
      if (!res.ok) throw new Error('Failed to fetch skill content')
      fullSkill = await res.json()
    } catch {
      addSystemMessage(`Failed to load Chat Skill${skillName ? ` '${skillName}'` : ''}. Please try again.`)
      return null
    }

    setActiveSkill({
      id: fullSkill.id,
      name: fullSkill.name,
      category: fullSkill.category,
      content: fullSkill.content,
    })

    if (conversationId) {
      updateConvMeta({ activeSkillId: fullSkill.id }).catch(() => {})
    }

    if (isLoading) {
      sendSkillInject({
        skill_id: fullSkill.id,
        skill_name: fullSkill.name,
        content: fullSkill.content,
      })
    }

    addSystemMessage(`[Chat Skill Active: ${fullSkill.name}] Category: ${fullSkill.category}`)
    return fullSkill
  }, [userId, isLoading, sendSkillInject, addSystemMessage, setActiveSkill, conversationId, updateConvMeta])

  // Handle /skill command
  const handleSkillCommand = useCallback(async (args: string) => {
    const query = args.trim()

    // /skill remove -- clear active skill
    if (query.toLowerCase() === 'remove') {
      setActiveSkill(null)
      if (conversationId) {
        updateConvMeta({ activeSkillId: '' }).catch(() => {})
      }
      addSystemMessage('Skill removed.')
      return
    }

    // Fetch all user chat skills
    let skills: ChatSkillSummary[]
    try {
      const res = await fetch(`/api/users/${userId}/chat-skills`)
      if (!res.ok) throw new Error('Failed to fetch chat skills')
      skills = await res.json()
    } catch {
      addSystemMessage('Failed to fetch chat skills. Please try again.')
      return
    }

    // /skill or /skill list -- show all skills grouped by category
    if (!query || query.toLowerCase() === 'list') {
      if (skills.length === 0) {
        addSystemMessage('No Chat Skills found. Create skills in Settings > Chat Skills.')
        return
      }
      const grouped: Record<string, ChatSkillSummary[]> = {}
      for (const s of skills) {
        const cat = s.category || 'general'
        if (!grouped[cat]) grouped[cat] = []
        grouped[cat].push(s)
      }
      let text = '[Chat Skills]\n'
      for (const [cat, items] of Object.entries(grouped).sort(([a], [b]) => a.localeCompare(b))) {
        text += `\n${cat}:\n`
        for (const s of items) {
          text += `  - ${s.name}${s.description ? ` -- ${s.description}` : ''}\n`
        }
      }
      text += '\nUsage: /skill <name> to load a skill, /skill remove to clear'
      addSystemMessage(text)
      return
    }

    // Try to match skill name from the beginning of the query.
    // This allows "/skill ssrf test the API" to match skill "ssrf" and
    // treat "test the API" as the inline message.
    const lowerQuery = query.toLowerCase()

    // Try matching progressively longer prefixes against skill names/IDs
    let bestMatch: ChatSkillSummary | null = null
    let remainingMessage = ''

    // First try: exact word-boundary matches (greedy -- longest skill name first)
    const sortedByNameLength = [...skills].sort((a, b) => b.name.length - a.name.length)
    for (const s of sortedByNameLength) {
      const lowerName = s.name.toLowerCase()
      if (lowerQuery === lowerName || lowerQuery.startsWith(lowerName + ' ')) {
        bestMatch = s
        remainingMessage = query.slice(s.name.length).trim()
        break
      }
      const lowerId = s.id.toLowerCase()
      if (lowerQuery === lowerId || lowerQuery.startsWith(lowerId + ' ')) {
        bestMatch = s
        remainingMessage = query.slice(s.id.length).trim()
        break
      }
    }

    // Fallback: partial match on first word only (no inline message in this case)
    if (!bestMatch) {
      const firstWord = lowerQuery.split(/\s+/)[0]
      const matches = skills.filter(s =>
        s.name.toLowerCase().includes(firstWord) || s.id.toLowerCase().includes(firstWord)
      )

      if (matches.length === 0) {
        addSystemMessage(`No Chat Skill found matching '${firstWord}'`)
        return
      }

      if (matches.length > 1) {
        const list = matches.map(s => `  - ${s.name} (${s.category})`).join('\n')
        addSystemMessage(`Multiple Chat Skills match '${firstWord}'. Be more specific:\n${list}`)
        return
      }

      bestMatch = matches[0]
      // If there was more text after the first word, treat it as inline message
      const afterFirst = query.slice(firstWord.length).trim()
      remainingMessage = afterFirst
    }

    // Activate the matched skill
    const fullSkill = await activateSkill(bestMatch.id, bestMatch.name)
    if (!fullSkill) return

    // If there is an inline message, send it as a normal query
    if (remainingMessage) {
      // Build the query with skill context prepended
      const finalQuestion = `[Chat Skill Context]\n${fullSkill.content}\n\n[User Query]\n${remainingMessage}`

      if (!conversationId && projectId && userId && sessionId) {
        const conv = await createConversation(sessionId)
        if (conv) {
          setConversationId(conv.id)
        }
      }

      if (isLoading) {
        const guidanceMessage: Message = {
          type: 'message',
          id: `guidance-${Date.now()}`,
          role: 'user',
          content: remainingMessage,
          isGuidance: true,
          timestamp: new Date(),
        }
        setChatItems((prev: ChatItem[]) => [...prev, guidanceMessage])
        sendGuidance(remainingMessage)
        saveMessage('guidance', { content: remainingMessage, isGuidance: true })
      } else {
        const userMessage: Message = {
          type: 'message',
          id: `user-${Date.now()}`,
          role: 'user',
          content: remainingMessage,
          timestamp: new Date(),
        }
        setChatItems((prev: ChatItem[]) => [...prev, userMessage])
        setIsLoading(true)

        const hasUserMessage = chatItems.some((item: ChatItem) => 'role' in item && item.role === 'user')
        if (!hasUserMessage) {
          updateConvMeta({ title: remainingMessage.substring(0, 100) })
        }

        try {
          sendQuery(finalQuestion)
        } catch {
          setIsLoading(false)
        }
      }
    }
  }, [userId, isLoading, addSystemMessage, setActiveSkill, activateSkill,
      conversationId, projectId, sessionId, createConversation, setConversationId,
      setChatItems, setIsLoading, sendQuery, sendGuidance, saveMessage, updateConvMeta, chatItems])

  const handleSend = useCallback(async () => {
    const question = inputValue.trim()
    if (!question || awaitingApproval || awaitingQuestion || awaitingToolConfirmation) return

    // Intercept /skill commands
    if (question.startsWith('/skill')) {
      const args = question.slice('/skill'.length).trim()
      setInputValue('')
      await handleSkillCommand(args)
      return
    }

    if (!conversationId && projectId && userId && sessionId) {
      const conv = await createConversation(sessionId)
      if (conv) {
        setConversationId(conv.id)
      }
    }

    if (isLoading) {
      // If active skill is set, inject it before the guidance message
      if (activeSkill) {
        sendSkillInject({
          skill_id: activeSkill.id,
          skill_name: activeSkill.name,
          content: activeSkill.content,
        })
      }

      const guidanceMessage: Message = {
        type: 'message',
        id: `guidance-${Date.now()}`,
        role: 'user',
        content: question,
        isGuidance: true,
        timestamp: new Date(),
      }
      setChatItems((prev: ChatItem[]) => [...prev, guidanceMessage])
      setInputValue('')
      sendGuidance(question)
      saveMessage('guidance', { content: question, isGuidance: true })
    } else {
      // Prepend active skill content to the query
      let finalQuestion = question
      if (activeSkill) {
        finalQuestion = `[Chat Skill Context]\n${activeSkill.content}\n\n[User Query]\n${question}`
      }

      const userMessage: Message = {
        type: 'message',
        id: `user-${Date.now()}`,
        role: 'user',
        content: question,
        timestamp: new Date(),
      }
      setChatItems(prev => [...prev, userMessage])
      setInputValue('')
      setIsLoading(true)

      const hasUserMessage = chatItems.some((item: ChatItem) => 'role' in item && item.role === 'user')
      if (!hasUserMessage) {
        updateConvMeta({ title: question.substring(0, 100) })
      }

      try {
        sendQuery(finalQuestion)
      } catch {
        setIsLoading(false)
      }
    }
  }, [inputValue, isLoading, awaitingApproval, awaitingQuestion, awaitingToolConfirmation,
      sendQuery, sendGuidance, sendSkillInject, activeSkill, handleSkillCommand, conversationId, projectId, userId, sessionId,
      createConversation, saveMessage, updateConvMeta, chatItems,
      setChatItems, setInputValue, setIsLoading, setConversationId])

  const handleApproval = useCallback((decision: 'approve' | 'modify' | 'abort') => {
    if (!awaitingApproval || isProcessingApproval.current || !awaitingApprovalRef.current) return

    isProcessingApproval.current = true
    awaitingApprovalRef.current = false

    setAwaitingApproval(false)
    setApprovalRequest(null)
    setIsLoading(true)

    const decisionMessage: Message = {
      type: 'message',
      id: `decision-${Date.now()}`,
      role: 'user',
      content: decision === 'approve'
        ? 'Approved phase transition'
        : decision === 'modify'
        ? `Modified: ${modificationText}`
        : 'Aborted phase transition',
      timestamp: new Date(),
    }
    setChatItems(prev => [...prev, decisionMessage])

    try {
      sendApproval(decision, decision === 'modify' ? modificationText : undefined)
      setModificationText('')
    } catch {
      setIsLoading(false)
      awaitingApprovalRef.current = false
      isProcessingApproval.current = false
    } finally {
      setTimeout(() => { isProcessingApproval.current = false }, 1000)
    }
  }, [modificationText, sendApproval, awaitingApproval,
      setAwaitingApproval, setApprovalRequest, setIsLoading, setChatItems, setModificationText])

  const handleTimelineToolConfirmation = useCallback((itemId: string, decision: 'approve' | 'reject') => {
    if (isProcessingToolConfirmation.current) return
    isProcessingToolConfirmation.current = true

    setAwaitingToolConfirmation(false)
    awaitingToolConfirmationRef.current = false
    setToolConfirmationRequest(null)
    setIsLoading(true)

    if (decision === 'reject') {
      setChatItems((prev: ChatItem[]) => prev.map((item: ChatItem) => {
        if (!('type' in item)) return item
        if (item.type === 'tool_execution' && item.id === itemId) {
          return { ...item, status: 'error' as const, final_output: 'Rejected by user' }
        }
        if (item.type === 'plan_wave' && item.id === itemId) {
          return { ...item, status: 'error' as const, interpretation: 'Rejected by user' }
        }
        return item
      }))
      pendingApprovalToolId.current = null
      pendingApprovalWaveId.current = null
    } else {
      setChatItems((prev: ChatItem[]) => {
        const matchingItem = prev.find((item: ChatItem) =>
          'type' in item && item.id === itemId && (item.type === 'plan_wave' || item.type === 'tool_execution')
        )
        if (matchingItem && 'type' in matchingItem) {
          if (matchingItem.type === 'plan_wave') {
            pendingApprovalWaveId.current = itemId
            pendingApprovalToolId.current = null
          } else {
            pendingApprovalToolId.current = itemId
            pendingApprovalWaveId.current = null
          }
        }
        return prev
      })
    }

    try {
      sendToolConfirmation(decision)
    } catch {
      setIsLoading(false)
    } finally {
      setTimeout(() => { isProcessingToolConfirmation.current = false }, 1000)
    }
  }, [sendToolConfirmation,
      setAwaitingToolConfirmation, setToolConfirmationRequest, setIsLoading, setChatItems])

  const handleAnswer = useCallback(() => {
    if (!awaitingQuestion || isProcessingQuestion.current || !awaitingQuestionRef.current) return
    if (!questionRequest) return

    isProcessingQuestion.current = true
    awaitingQuestionRef.current = false

    setAwaitingQuestion(false)
    setQuestionRequest(null)
    setIsLoading(true)

    const answer = questionRequest.format === 'text'
      ? answerText
      : selectedOptions.join(', ')

    const answerMessage: Message = {
      type: 'message',
      id: `answer-${Date.now()}`,
      role: 'user',
      content: `Answer: ${answer}`,
      timestamp: new Date(),
    }
    setChatItems(prev => [...prev, answerMessage])

    try {
      sendAnswer(answer)
      setAnswerText('')
      setSelectedOptions([])
    } catch {
      setIsLoading(false)
      awaitingQuestionRef.current = false
      isProcessingQuestion.current = false
    } finally {
      setTimeout(() => { isProcessingQuestion.current = false }, 1000)
    }
  }, [questionRequest, answerText, selectedOptions, sendAnswer, awaitingQuestion,
      setAwaitingQuestion, setQuestionRequest, setIsLoading, setChatItems, setAnswerText, setSelectedOptions])

  const handleStop = useCallback(() => {
    setIsStopping(true)
    sendStop()
  }, [sendStop, setIsStopping])

  const handleResume = useCallback(() => {
    sendResume()
    setIsStopped(false)
    setIsStopping(false)
    setIsLoading(true)
  }, [sendResume, setIsStopped, setIsStopping, setIsLoading])

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInputValue(e.target.value)
    e.target.style.height = 'auto'
    e.target.style.height = `${Math.min(e.target.scrollHeight, 120)}px`
  }

  return {
    inputRef,
    handleSend,
    handleApproval,
    handleTimelineToolConfirmation,
    handleAnswer,
    handleStop,
    handleResume,
    handleKeyDown,
    handleInputChange,
    activateSkill,
  }
}
