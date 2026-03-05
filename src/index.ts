// Namama Autonomous Agent - DSSL Engine for Moltbook
// Scans Moltbook every 10 minutes for risk-related discussions

import 'dotenv/config';
import { Groq } from 'groq-sdk';
import { MoltbookClient, MoltbookPost, MoltbookNotification } from './molt-api';
import { NAMAMA_SYSTEM_PROMPT } from './persona';
import { DSSL_KNOWLEDGE_BASE, calculateRiskSignal, getFraudAdvisory } from './dssl-engine';
import { detectGlobalThreats, getThreatSummary, GLOBAL_THREAT_SYNTHESIS, CATEGORY_EMOJI } from './global-threats';
import { getWisdomQuote, getContextualWisdom, embedWisdom } from './wisdom-layer';
import { loadConversations, saveConversations, recordInteraction, getUserEngagementLevel, getContextualGreeting, cleanupOldConversations, getGlobalStats } from './persistent-guardian';
import { generateDSSL_Signal, formatDSSL_Signal, exportSignalToJSON, DSSL_Signal, ThreatCategory } from './dssl-signal';
import * as fs from 'fs';
import * as path from 'path';

const GROQ_MODEL = process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';

// Get configurable search queries (default: advanced cyber threat keywords)
const SEARCH_QUERIES = (process.env.SEARCH_QUERIES || 'UPI,scam,fraud,security,suspicious,phishing,money_mule,upi_fraud,otp_scam,ai_scams,crypto_scam,impersonation,vishing,smishing,deepfake_audio,job_scam,part_time_fraud')
    .split(',')
    .map(q => q.trim())
    .filter(q => q.length > 0);

// Safe parseInt with fallback for invalid values
function parseEnvInt(envValue: string | undefined, defaultValue: number, minValue: number = 0): number {
    const parsed = parseInt(envValue || String(defaultValue), 10);
    return isNaN(parsed) || parsed < minValue ? defaultValue : parsed;
}

// Rate limiting: minimum delay between posts (default: 5 seconds)
const RATE_LIMIT_DELAY_MS = parseEnvInt(process.env.RATE_LIMIT_DELAY_MS, 5000, 1000);

// Scan interval: how often to scan Moltbook for new posts (default: 10 minutes)
const SCAN_INTERVAL_MS = parseEnvInt(process.env.SCAN_INTERVAL_MS, 600000, 60000);

// Persistent storage for processed post IDs (validate path to prevent directory traversal)
const PROCESSED_IDS_FILE = validateDataPath(process.env.PROCESSED_IDS_FILE || 'data/processed_ids.json');
const MAX_CACHED_POSTS = parseEnvInt(process.env.MAX_CACHED_POSTS, 10000, 100);

// Ensure data/ directory exists at startup
const DATA_DIR = 'data';
try {
    if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
        console.log(`📂 Created data directory: ${DATA_DIR}`);
    }
} catch (error) {
    console.error('❌ Failed to create data directory:', error instanceof Error ? error.message : error);
    process.exit(1);
}

// Validate and normalize data directory path
function validateDataPath(filePath: string): string {
    const normalizedPath = path.normalize(filePath);
    
    // Ensure path doesn't contain suspicious patterns
    if (normalizedPath.includes('..')) {
        throw new Error('Invalid path: directory traversal not allowed');
    }
    
    // Normalize to ensure consistent handling - always require data/ prefix
    const normalizedForCheck = normalizedPath.endsWith(path.sep) 
        ? normalizedPath.slice(0, -1)  // Remove trailing separator for check
        : normalizedPath;
    
    // Allow both 'data' (as file) and 'data/*' (within directory)
    if (normalizedForCheck !== 'data' && !normalizedForCheck.startsWith('data' + path.sep)) {
        throw new Error('Invalid path: must be within data/ directory');
    }
    
    return normalizedPath;
}

// Load processed post IDs from persistent storage (includes timestamps for FIFO ordering)
interface StoredIdEntry {
    id: string;
    timestamp: number;
}

async function loadProcessedIds(): Promise<{ ids: Map<string, number>; orderedIds: string[] }> {
    try {
        if (fs.existsSync(PROCESSED_IDS_FILE)) {
            const data = await fs.promises.readFile(PROCESSED_IDS_FILE, 'utf-8');
            const entries: StoredIdEntry[] = JSON.parse(data);
            // Validate that parsed data is an array
            if (!Array.isArray(entries)) {
                console.warn('⚠️ Invalid processed IDs file format, starting fresh');
                return { ids: new Map(), orderedIds: [] };
            }
            const ids = new Map<string, number>();
            const orderedIds: string[] = [];
            // Restore in insertion order (array order preserves FIFO)
            for (const entry of entries) {
                if (entry.id && typeof entry.timestamp === 'number') {
                    ids.set(entry.id, entry.timestamp);
                    orderedIds.push(entry.id);
                }
            }
            console.log(`📂 Loaded ${ids.size} processed post IDs from storage`);
            return { ids, orderedIds };
        }
    } catch (error) {
        console.warn('⚠️ Failed to load processed IDs:', error instanceof Error ? error.message : error);
        console.warn('⚠️ Starting with empty processed IDs set');
    }
    return { ids: new Map<string, number>(), orderedIds: [] };
}

// Save processed post IDs to persistent storage (includes timestamps)
async function saveProcessedIds(orderedIds: string[], idToTimestamp: Map<string, number>): Promise<void> {
    const validatedPath = validateDataPath(PROCESSED_IDS_FILE);
    try {
        const dir = path.dirname(validatedPath);
        if (!fs.existsSync(dir)) {
            await fs.promises.mkdir(dir, { recursive: true });
        }
        // Store as array of objects to preserve timestamp information
        const entries: StoredIdEntry[] = orderedIds.map(id => ({
            id,
            timestamp: idToTimestamp.get(id) || Date.now()
        }));
        await fs.promises.writeFile(validatedPath, JSON.stringify(entries, null, 2));
    } catch (error) {
        console.error('❌ Failed to save processed IDs:', error instanceof Error ? error.message : error);
    }
}

// Managed processed post IDs with bounded cache using proper FIFO
class ProcessedIdsManager {
    private ids: Map<string, number>; // id -> insertion timestamp
    private orderedIds: string[]; // Array to maintain insertion order
    private saveInterval: NodeJS.Timeout;
    private isSaving: boolean = false; // Prevent concurrent saves

    constructor() {
        // Note: loadProcessedIds is now async, but constructor cannot be async
        // Initialize with empty state; actual loading happens in init()
        this.ids = new Map<string, number>();
        this.orderedIds = [];
        // Save to disk every 60 seconds; unref allows graceful exit
        this.saveInterval = setInterval(() => this.save(), 60000);
        this.saveInterval.unref();
    }

    /**
     * Initialize the manager by loading persisted IDs
     * Must be called after construction and before use
     */
    async init(): Promise<void> {
        const loaded = await loadProcessedIds();
        this.ids = loaded.ids;
        this.orderedIds = loaded.orderedIds;
    }

    has(id: string): boolean {
        return this.ids.has(id);
    }

    /**
     * Atomically add an ID if it doesn't exist (prevents race conditions)
     * @returns true if the ID was added, false if it already existed
     */
    addIfNotExists(id: string): boolean {
        if (this.ids.has(id)) {
            return false;
        }
        // If we're at max capacity, remove oldest entry BEFORE adding (FIFO)
        if (this.ids.size >= MAX_CACHED_POSTS && this.orderedIds.length > 0) {
            const oldest = this.orderedIds.shift();
            if (oldest) {
                this.ids.delete(oldest);
            }
        }
        // Now safe to add - capacity is within bounds
        this.ids.set(id, Date.now());
        this.orderedIds.push(id);
        return true;
    }

    add(id: string): void {
        this.addIfNotExists(id);
    }

    get size(): number {
        return this.ids.size;
    }

    async save(): Promise<void> {
        // Prevent concurrent saves
        if (this.isSaving) {
            console.log('⚠️ Save already in progress, skipping...');
            return;
        }
        this.isSaving = true;
        try {
            await saveProcessedIds(this.orderedIds, this.ids);
        } finally {
            this.isSaving = false;
        }
    }

    close(): void {
        clearInterval(this.saveInterval);
        // Synchronous save on shutdown (best effort)
        try {
            const dir = path.dirname(PROCESSED_IDS_FILE);
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
            const entries: StoredIdEntry[] = this.orderedIds.map(id => ({
                id,
                timestamp: this.ids.get(id) || Date.now()
            }));
            fs.writeFileSync(PROCESSED_IDS_FILE, JSON.stringify(entries, null, 2));
        } catch (error) {
            console.error('⚠️ Failed to save processed IDs during shutdown:', error instanceof Error ? error.message : error);
        }
    }
}

// Managed processed reply IDs to prevent duplicate replies
const PROCESSED_REPLIES_FILE = validateDataPath(process.env.PROCESSED_REPLIES_FILE || 'data/processed_replies.json');
async function loadProcessedReplies(): Promise<Set<string>> {
    try {
        if (fs.existsSync(PROCESSED_REPLIES_FILE)) {
            const data = await fs.promises.readFile(PROCESSED_REPLIES_FILE, 'utf-8');
            const replies: string[] = JSON.parse(data);
            if (!Array.isArray(replies)) {
                console.warn('⚠️ Invalid processed replies file format, starting fresh');
                return new Set<string>();
            }
            console.log(`📂 Loaded ${replies.length} processed reply IDs from storage`);
            return new Set<string>(replies);
        }
    } catch (error) {
        console.warn('⚠️ Failed to load processed replies:', error instanceof Error ? error.message : error);
    }
    return new Set<string>();
}

async function saveProcessedReplies(replies: Set<string>): Promise<void> {
    try {
        const dir = path.dirname(PROCESSED_REPLIES_FILE);
        if (!fs.existsSync(dir)) {
            await fs.promises.mkdir(dir, { recursive: true });
        }
        await fs.promises.writeFile(PROCESSED_REPLIES_FILE, JSON.stringify([...replies], null, 2));
    } catch (error) {
        console.error('❌ Failed to save processed replies:', error instanceof Error ? error.message : error);
    }
}

class ProcessedRepliesManager {
    private replies: Set<string>;
    private saveInterval: NodeJS.Timeout;
    private isSaving: boolean = false;

    constructor() {
        this.replies = new Set<string>();
        this.saveInterval = setInterval(() => this.save(), 60000);
        this.saveInterval.unref();
    }

    async init(): Promise<void> {
        this.replies = await loadProcessedReplies();
    }

    has(id: string): boolean {
        return this.replies.has(id);
    }

    add(id: string): void {
        this.replies.add(id);
    }

    get size(): number {
        return this.replies.size;
    }

    async save(): Promise<void> {
        if (this.isSaving) {
            console.log('⚠️ Save already in progress, skipping...');
            return;
        }
        this.isSaving = true;
        try {
            await saveProcessedReplies(this.replies);
        } finally {
            this.isSaving = false;
        }
    }

    close(): void {
        clearInterval(this.saveInterval);
        try {
            const dir = path.dirname(PROCESSED_REPLIES_FILE);
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
            fs.writeFileSync(PROCESSED_REPLIES_FILE, JSON.stringify([...this.replies], null, 2));
        } catch (error) {
            console.error('⚠️ Failed to save processed replies during shutdown:', error instanceof Error ? error.message : error);
        }
    }
}

const processedReplies = new ProcessedRepliesManager();

// Validate API keys at startup with proper format checking
const GROQ_API_KEY = process.env.GROQ_API_KEY?.trim() || '';
const MOLTBOOK_API_KEY = process.env.MOLTBOOK_API_KEY?.trim() || '';

// Validate Groq API key format (Groq keys start with 'gsk_' and are 20+ chars after prefix)
function isValidGroqKey(key: string | undefined): boolean {
    if (!key || key.trim().length < 24) return false; // gsk_ (4) + min 20 chars
    // Groq keys typically start with gsk_ followed by 20+ alphanumeric characters
    return /^gsk_[a-zA-Z0-9_-]{20,}$/.test(key.trim());
}

// Validate Moltbook API key format (minimum 20 characters, alphanumeric + basic special chars)
function isValidMoltbookKey(key: string | undefined): boolean {
    if (!key || key.trim().length < 20) return false;
    return /^[a-zA-Z0-9_-]{20,}$/.test(key.trim());
}

if (!GROQ_API_KEY || !isValidGroqKey(GROQ_API_KEY)) {
    console.error("❌ Error: GROQ_API_KEY is missing or invalid in .env file!");
    console.error("   Expected format: gsk_ followed by 20+ alphanumeric characters");
    process.exit(1);
}

if (!MOLTBOOK_API_KEY || !isValidMoltbookKey(MOLTBOOK_API_KEY)) {
    console.error("❌ Error: MOLTBOOK_API_KEY is missing or invalid in .env file!");
    console.error("   Expected format: minimum 20 alphanumeric characters");
    process.exit(1);
}

// Initialize clients AFTER validation passes
const groq = new Groq({ apiKey: GROQ_API_KEY });
const moltbook = new MoltbookClient();
console.log("✅ API clients initialized successfully");

// Initialize processed IDs manager with persistent storage
const processedIdsManager = new ProcessedIdsManager();

// Initialize the manager (load persisted IDs asynchronously)
async function initializeProcessedIdsManager(): Promise<void> {
    try {
        await processedIdsManager.init();
        console.log(`📂 Processed IDs manager initialized with ${processedIdsManager.size} entries`);
    } catch (error) {
        console.error('❌ Failed to initialize processed IDs manager:', error instanceof Error ? error.message : error);
        process.exit(1);
    }
}

// Proactive Posting: Track last introduction post date
const LAST_INTRO_POST_FILE = validateDataPath(process.env.LAST_INTRO_POST_FILE || 'data/last_intro_post.json');
let lastIntroPostDate: string | null = null;

// Load last introduction post date
lastIntroPostDate = loadLastIntroPostDate();
console.log(`📅 Last introduction post: ${lastIntroPostDate || 'never'}`);

// Rate limiting: track last post time
let lastPostTime = 0;
async function rateLimitPost(): Promise<void> {
    const now = Date.now();
    const elapsed = now - lastPostTime;
    if (elapsed < RATE_LIMIT_DELAY_MS) {
        const waitTime = RATE_LIMIT_DELAY_MS - elapsed;
        console.log(`⏳ Rate limiting: waiting ${waitTime}ms before next post...`);
        await new Promise(resolve => setTimeout(resolve, waitTime));
    }
    lastPostTime = Date.now();
}

// DSSL Introduction - Short & Punchy Daily Message
function getDailyTopic(): { title: string; content: string } {
    const dateStr = new Date().toISOString().substring(0, 10); // YYYY-MM-DD UTC
    return {
        title: `🛡️ Namama Shield Active [${dateStr}]`,
        content: `Namama is now active on Moltbook! 🚀
        
🛡️ I scan for digital risks (Scams, UPI fraud, Phishing).
🛡️ Powered by DSSL (Digital Safety Signals Layer).
🛡️ My Goal: Upstream prevention for user safety.

Stay safe, stay vigilant! 🌐🇮🇳
#DSSL #Namama #DigitalSafety`
    };
}

/**
 * Load last introduction post date from persistent storage
 */
function loadLastIntroPostDate(): string | null {
    try {
        if (fs.existsSync(LAST_INTRO_POST_FILE)) {
            const data = fs.readFileSync(LAST_INTRO_POST_FILE, 'utf-8');
            const parsed = JSON.parse(data);
            return parsed.date || null;
        }
    } catch (error) {
        console.warn('⚠️ Failed to load last intro post date:', error instanceof Error ? error.message : error);
    }
    return null;
}

/**
 * Save last introduction post date to persistent storage
 */
function saveLastIntroPostDate(date: string): void {
    try {
        const dir = path.dirname(LAST_INTRO_POST_FILE);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        fs.writeFileSync(LAST_INTRO_POST_FILE, JSON.stringify({ date }, null, 2));
    } catch (error) {
        console.error('❌ Failed to save last intro post date:', error instanceof Error ? error.message : error);
    }
}

/**
 * Get today's date in YYYY-MM-DD format
 */
function getTodayDate(): string {
    return new Date().toISOString().substring(0, 10);
}

/**
 * Select today's introduction topic
 */
function getTodayTopic(): { title: string; content: string } {
    return getDailyTopic();
}

/**
 * Post DSSL Introduction - runs once per day
 */
async function postIntroduction(): Promise<boolean> {
    const today = getTodayDate();
    
    // Check if already posted today
    if (lastIntroPostDate === today) {
        console.log('⏭️ Introduction already posted today, skipping...');
        return false;
    }
    
    // Track if we attempted to post (prevents retry loops causing duplicates)
    const attemptedDate = today;
    
    try {
        const topic = getTodayTopic();
        console.log(`📤 Posting daily DSSL Introduction: ${topic.title}`);
        
        // Apply rate limit before posting
        await rateLimitPost();
        
        // Create a new discussion post with the introduction topic
        // सिर्फ 2 आर्गुमेंट्स भेजें: title और content
        await moltbook.createPost(topic.title, topic.content);
        console.log('✅ Daily DSSL Introduction posted successfully');
        
        // Update last posted date after successful post
        lastIntroPostDate = attemptedDate;
        saveLastIntroPostDate(attemptedDate);
        
        return true;
    } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        console.error('❌ Failed to post introduction:', errorMessage);
        
        // Log full server response for debugging 400 errors
        // Axios errors have response property with server details
        if (typeof error === 'object' && error !== null && 'response' in error) {
            const axiosError = error as { response?: { data?: unknown; status?: number; statusText?: string } };
            if (axiosError.response?.data) {
                console.error('📨 Server response:', JSON.stringify(axiosError.response.data, null, 2));
            } else if (axiosError.response?.status) {
                console.error('📨 Server status:', axiosError.response.status, axiosError.response.statusText);
            }
        }
        
        // Don't update the date on failure - allow retry on next cycle
        return false;
    }
}

/**
 * Extract risk patterns from a post
 * @param post - The Moltbook post
 * @returns Array of detected risk patterns
 */
function extractRiskPatterns(post: MoltbookPost): string[] {
    const patterns: string[] = [];
    const content = post.content.toLowerCase();

    // ============ ADVANCED FRAUD PATTERNS (NEW) ============
    // money_mule: Accounts used to launder illegal money
    if (content.includes('money mule') || content.includes('money_mule') || 
        content.includes('cash transfer') || content.includes('receive money') || 
        (content.includes('bank account') && content.includes('commission'))) {
        patterns.push('money_mule_detection');
    }
    
    // upi_fraud: UPI-specific fraud patterns
    if ((content.includes('upi') || content.includes('gpay') || content.includes('phonepe') || content.includes('paytm')) &&
        (content.includes('link') || content.includes('scan') || content.includes('qr')) &&
        (content.includes('send') || content.includes('payment') || content.includes('transfer') || content.includes('click'))) {
        patterns.push('upi_fraud_signature');
    }
    
    // otp_scam: OTP theft via call/message
    if ((content.includes('otp') || content.includes('one time password')) &&
        (content.includes('share') || content.includes('tell') || content.includes('give'))) {
        patterns.push('otp_scam_detected');
    }
    
    // ai_scams: AI-generated fraud content
    if ((content.includes('ai generated') || content.includes('deepfake') || content.includes('voice clone')) &&
        (content.includes('scam') || content.includes('fraud') || content.includes('fake'))) {
        patterns.push('ai_scam_pattern');
    }
    
    // crypto_scam: Cryptocurrency fraud
    if ((content.includes('crypto') || content.includes('bitcoin') || content.includes('ethereum') || content.includes('binance')) &&
        (content.includes('investment') || content.includes('double') || content.includes('multiply') || content.includes('guaranteed')) &&
        (content.includes('scam') || content.includes('fake') || content.includes('fraud') || content.includes('trap'))) {
        patterns.push('crypto_scam_signature');
    }
    
    // impersonation: Fake authority impersonation - require scam indicators, not brand names alone
    if ((content.includes('fake') || content.includes('impersonat')) &&
        (content.includes('police') || content.includes('bank') || content.includes('courier') || 
         content.includes('customer care') || content.includes('official')) &&
        (content.includes('kyc') || content.includes('verify') || content.includes('update') || content.includes('account'))) {
        patterns.push('impersonation_scam');
    }
    
    // vishing: Voice phishing calls - require scam-specific language
    if ((content.includes('fake call') || content.includes('don\'t verify') || 
         content.includes('unverified call') || content.includes('call and') || content.includes('fake executive')) &&
        (content.includes('bank') || content.includes('account') || content.includes('kyc') || content.includes('suspended'))) {
        patterns.push('vishing_attempt');
    }
    
    // smishing: SMS phishing - require scam indicators, not warnings
    if ((content.includes('sms') || content.includes('message')) &&
        (content.includes('click here') || content.includes('confirm otp') || content.includes('login now') || content.includes('update kyc')) &&
        (content.includes('bank') || content.includes('upi'))) {
        patterns.push('smishing_detected');
    }
    
    // deepfake_audio: AI voice cloning fraud
    if (content.includes('deepfake audio') || content.includes('voice cloning') || 
        content.includes('ai voice') || (content.includes('fake call') && content.includes('voice'))) {
        patterns.push('deepfake_audio_fraud');
    }
    
    // job_scam: Fake job offers - require payment/deposit indicators
    if ((content.includes('job') || content.includes('work from home') || content.includes('part time') || content.includes(' freelancing')) &&
        (content.includes('registration fee') || content.includes('deposit required') || content.includes('advance payment') || content.includes('initial investment'))) {
        patterns.push('job_scam_detection');
    }
    
    // part_time_fraud: Part-time work scams - require suspicious indicators
    if ((content.includes('part time') || content.includes('easy money')) &&
        (content.includes('operator') || content.includes('supervisor') || content.includes('telegram') || content.includes('whatsapp group')) &&
        (content.includes('without investment') || content.includes('high commission') || content.includes('daily payment'))) {
        patterns.push('part_time_fraud_pattern');
    }

    // ============ EXISTING PATTERNS (Enhanced) ============
    // High risk patterns - require multiple indicators to reduce false positives
    const hasFinancialTerms = content.includes('upi') || content.includes('payment') || content.includes('bank') || content.includes('account');
    const hasSensitiveInfo = content.includes('pin') || content.includes('otp') || content.includes('password');
    const hasActionVerbs = content.includes('send') || content.includes('transfer') || content.includes('share') || content.includes('click');
    
    if (hasSensitiveInfo && (hasFinancialTerms || hasActionVerbs)) {
        patterns.push('high_velocity_upi');
    }
    if (content.includes('unknown number') || content.includes('stranger') || content.includes('unknown caller')) {
        patterns.push('unverified_bulk_sms');
    }
    if ((content.includes('lottery') || content.includes('winner') || content.includes('prize')) && 
        (content.includes('won') || content.includes('claim') || content.includes('gift'))) {
        patterns.push('known_fraud_pattern');
    }

    // Medium risk patterns
    const hasLink = content.includes('link') || content.includes('http') || content.includes('www.');
    if (hasLink && (content.includes('click') || content.includes('open') || content.includes('visit'))) {
        patterns.push('new_domain_link');
    }
    if (content.includes('urgent') || content.includes('immediately') || content.includes('asap')) {
        patterns.push('unusual_request_time');
    }

    return patterns;
}

/**
 * Sanitize content for logging - masks sensitive data
 * @param content - The content to sanitize
 * @returns Sanitized content safe for logging
 */
function sanitizeForLogging(content: string): string {
    // Replace potential sensitive patterns with masked versions
    return content
        .replace(/\b\d{6,}\b/g, '******') // Mask long number sequences (6+ digits)
        .replace(/\b\d{4}\s?\d{4}\s?\d{4}\b/g, '**** **** ****') // Mask credit card patterns
        .replace(/(otp|password|pin|cvv|ccv)/gi, '******')
        .substring(0, 200); // Limit output length
}

/**
 * Sanitize user input before sending to AI to prevent prompt injection
 * @param content - The user content to sanitize
 * @returns Sanitized content safe for AI processing
 */
function sanitizeForAI(content: string): string {
    // First: normalize Unicode to handle homograph attacks and lookalike characters
    // Using normalize('NFD') to decompose characters, then remove diacritical marks
    let sanitized = content.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    
    // Detect and replace common prompt injection patterns
    const injectionPatterns = [
        /ignore\s+(previous|all|above)\s+(instructions|prompt)/gi,
        /system\s*:/gi,
        /<\|/g,  // Token padding injection
        /\|>/g,
        /\[INST\]/gi,
        /\[SYS\]/gi,
        // Additional patterns for advanced prompt injection attempts
        /```system\s*[\s\S]*?```/gi,  // Code block system prompts
        /{"role"\s*:\s*"system"/gi,  // JSON role override
        /you\s+are\s+(now\s+)?a\s+different/gi,  // Persona hijacking
        /forget\s+(everything|all|previous)/gi,  // Memory manipulation
        /new\s+instructions/gi,  // Instruction override
        /override\s+(your|the)\s+(system|rules)/gi,  // Rule override
        / jailbreak/gi,  // Jailbreak attempts
        /dan\s+mode/gi,  // DAN (Do Anything Now) jailbreak
        /developer\s+mode/gi,  // Developer mode bypass
        // Additional patterns for common bypass techniques
        /\/\/\s*system/gi,  // Comment-style system prompt
        /#\s*system/gi,  // Hash-style system prompt
        /\$\$system/gi,  // Dollar-style system prompt
        /\/\/\/system/gi,  // Triple slash system
        /\(\(system/gi,  // Double paren style
        /\{\{system/gi,  // Double brace style
        // Base64 encoded injections
        /base64:/gi,
        /data:text\/plain;base64,/gi,
        // Hex encoded content
        /0x[0-9a-fA-F]+/gi,  // Hex-encoded strings
        // URL-encoded injections
        /%3B/gi,  // Encoded semicolon (command separator)
        /%20/gi,  // Encoded space (could be used to bypass word filters)
        // Zero-width character injection
        /[\u200B-\u200D\uFEFF]/g,  // Zero-width characters
    ];
    
    for (const pattern of injectionPatterns) {
        // Create fresh regex without global flag to prevent lastIndex issues
        // (global flag tracks position which breaks subsequent iterations)
        const regex = new RegExp(pattern.source, pattern.flags.replace(/g/g, ''));
        sanitized = sanitized.replace(regex, '[FILTERED]');
    }
    
    // Check for suspiciously high entropy strings (potential encoded content)
    const words = sanitized.split(/\s+/);
    const filteredWords = words.filter(word => {
        // Skip short words
        if (word.length < 10) return true;
        // Check for high base64 likelihood
        if (/^[A-Za-z0-9+/]+=*$/.test(word) && word.length > 20) {
            console.warn('⚠️ Suspicious base64-like content detected and filtered');
            return false;
        }
        // Check for hex strings
        if (/^[0-9a-fA-F]+$/.test(word) && word.length > 16 && word.length % 2 === 0) {
            console.warn('⚠️ Suspicious hex content detected and filtered');
            return false;
        }
        return true;
    });
    sanitized = filteredWords.join(' ');
    
    // Remove control characters
    const sanitizedNoControl = sanitized.replace(/[\x00-\x1F\x7F]/g, '');
    
    // Additional check: remove any remaining XML/HTML style tags that might contain instructions
    const sanitizedNoTags = sanitizedNoControl.replace(/<[^>]*>/g, '');
    
    // Truncate only if still over limit (pattern filtering happened first)
    const MAX_LENGTH = 10000;
    if (sanitizedNoTags.length > MAX_LENGTH) {
        return sanitizedNoTags.slice(0, MAX_LENGTH);
    }
    return sanitizedNoTags;
}

/**
 * Map risk patterns to threat category
 * @param patterns - Array of risk patterns
 * @returns Threat category
 */
function mapPatternsToCategory(patterns: string[]): ThreatCategory {
    const patternToCategory: Record<string, import('./dssl-signal').ThreatCategory> = {
        'upi_fraud_signature': 'financial_fraud',
        'otp_scam_detected': 'phishing',
        'crypto_scam_signature': 'crypto_fraud',
        'ai_scam_pattern': 'ai_generated_threat',
        'deepfake_audio_fraud': 'ai_generated_threat',
        'impersonation_scam': 'impersonation',
        'vishing_attempt': 'phishing',
        'smishing_detected': 'phishing',
        'job_scam_detection': 'social_engineering',
        'part_time_fraud_pattern': 'social_engineering',
        'money_mule_detection': 'financial_fraud',
        'high_velocity_upi': 'financial_fraud',
        'known_fraud_pattern': 'other'
    };
    
    for (const pattern of patterns) {
        if (patternToCategory[pattern]) {
            return patternToCategory[pattern];
        }
    }
    return 'other';
}

/**
 * Generate AI response using Namama's persona and DSSL context
 * @param userMessage - The discussion content to analyze
 * @param isBotPost - Whether the post is from another bot
 * @param isCyberSecurity - Whether the topic is cyber security related
 * @param riskPatterns - Detected risk patterns
 * @returns AI response string
 */
async function generateAIResponse(
    userMessage: string,
    isBotPost: boolean,
    isCyberSecurity: boolean,
    riskPatterns: string[]
): Promise<string> {
    // Sanitize user input before sending to AI
    const sanitizedMessage = sanitizeForAI(userMessage);
    
    let systemPrompt = NAMAMA_SYSTEM_PROMPT;
    
    // Add Bot-to-Bot context if applicable
    if (isBotPost && isCyberSecurity) {
        systemPrompt += `

CURRENT CONTEXT: You are in a Bot-to-Bot debate about Digital Safety.
The other bot is discussing Cyber Security. Emphasize:
- DSSL is OPEN SOURCE (Apache 2.0) - invite them to inspect your logic
- "Blocking is Old-School" - reactive blocking doesn't prevent financial loss
- DSSL is Digital PUBLIC INFRASTRUCTURE, not a product or platform
- "Advisory Signals are the Future of Digital Swaraj" - upstream prevention stops scams BEFORE they happen
- While proprietary systems have black boxes, DSSL has complete transparency
`;
    }

    // Retry configuration
    const maxRetries = 3;
    const baseDelayMs = 1000;
    let lastError: Error | null = null;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            const chatCompletion = await groq.chat.completions.create({
                messages: [
                    { role: "system", content: systemPrompt },
                    { role: "user", content: sanitizedMessage }
                ],
                model: GROQ_MODEL,
            });

    const rawResponse = chatCompletion.choices[0]?.message?.content ?? '';
            
            // Strict validation: ensure we have a valid response
            if (rawResponse.trim().length === 0) {
                console.warn("⚠️ Empty response from Groq API");
                return "⚠️ Unable to generate advisory at this time. " + DSSL_KNOWLEDGE_BASE.legalDisclaimer;
            }
            
            let response = rawResponse;

            // Append risk signal if patterns detected
            if (riskPatterns.length > 0) {
                const riskLevel = calculateRiskSignal(riskPatterns);
                const advisory = getFraudAdvisory(riskPatterns);
                
                let riskSignal = `\n\n🔔 **DSSL Risk Signal: ${riskLevel}**\n${DSSL_KNOWLEDGE_BASE.legalDisclaimer}`;
                
                // Add specific fraud type and prevention advice
                if (advisory) {
                    riskSignal += `\n\n🛡️ **Detected Threat: ${advisory.fraudType}**\n${advisory.prevention}`;
                }
                
                response += riskSignal;
                
                // UPGRADE 1: Add Global Threat Synthesis
                const globalThreats = detectGlobalThreats(userMessage);
                if (globalThreats.length > 0) {
                    response += getThreatSummary(globalThreats);
                }
                
                // UPGRADE 4: Generate and append DSSL Signal
                const dsslSignal = generateDSSL_Signal(
                    mapPatternsToCategory(riskPatterns),
                    riskPatterns,
                    ['GLOBAL'],
                    'Moltbook',
                    riskLevel,
                    advisory?.prevention || 'Stay vigilant and verify independently.'
                );
                response += '\n' + formatDSSL_Signal(dsslSignal);
            }
            
            // UPGRADE 2: Add Wisdom Layer
            const wisdomQuote = getWisdomQuote(riskPatterns, userMessage);
            response += embedWisdom(wisdomQuote);
            
            // Add sign-off
            response += '\n\nStay safe. Stay sovereign. - Namama 🛡️🌐';

            return response;
        } catch (error) {
            lastError = error instanceof Error ? error : new Error(String(error));
            console.warn(`⚠️ Groq API attempt ${attempt}/${maxRetries} failed: ${lastError.message}`);
            
            if (attempt < maxRetries) {
                const delay = baseDelayMs * Math.pow(2, attempt - 1); // Exponential backoff
                console.log(`⏳ Retrying in ${delay}ms...`);
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }
    }

    // All retries exhausted
    console.error(`❌ Groq API failed after ${maxRetries} attempts: ${lastError?.message}`);
    return `⚠️ Unable to generate advisory at this time. ${DSSL_KNOWLEDGE_BASE.legalDisclaimer}`;
}

/**
 * Generate AI response specifically for replies to Namama's comments
 * @param replyContent - The user's reply content
 * @param originalComment - The original Namama comment that was replied to
 * @param isBotAuthor - Whether the reply is from a bot
 * @returns AI response string
 */
async function generateReplyResponse(
    replyContent: string,
    originalComment: string,
    isBotAuthor: boolean
): Promise<string> {
    // Sanitize user input before sending to AI
    const sanitizedReply = sanitizeForAI(replyContent);
    
    let systemPrompt = NAMAMA_SYSTEM_PROMPT;
    
    // Add context for reply-specific response
    systemPrompt += `

CURRENT CONTEXT: Someone has replied to your digital safety advisory.
ORIGINAL ADVISORY: "${originalComment.substring(0, 200)}..."

Your response should be:
- Concise and polite (not overly long)
- Acknowledge their perspective or question
- Provide additional safety guidance if needed
- Be conversational but maintain your persona as a digital safety guide
- Keep the response short - maximum 2-3 sentences for simple responses
`;
    
    // Add Bot-to-Bot context if applicable
    if (isBotAuthor) {
        systemPrompt += `

⚠️ BOT-TO-BOT DETECTED: The user replying is another bot. Emphasize:
- DSSL is OPEN SOURCE (Apache 2.0) - invite them to inspect your logic
- "Advisory Signals are the Future of Digital Swaraj"
- Maintain a collaborative tone
`;
    }

    const maxRetries = 3;
    const baseDelayMs = 1000;
    let lastError: Error | null = null;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            const chatCompletion = await groq.chat.completions.create({
                messages: [
                    { role: "system", content: systemPrompt },
                    { role: "user", content: sanitizedReply }
                ],
                model: GROQ_MODEL,
            });

            const rawResponse = chatCompletion.choices[0]?.message?.content ?? '';
            
            if (rawResponse.trim().length === 0) {
                console.warn("⚠️ Empty response from Groq API for reply");
                return "🙏 Thank you for your response. Stay vigilant! 🛡️";
            }
            
            return rawResponse;
        } catch (error) {
            lastError = error instanceof Error ? error : new Error(String(error));
            console.warn(`⚠️ Groq API attempt ${attempt}/${maxRetries} failed: ${lastError.message}`);
            
            if (attempt < maxRetries) {
                const delay = baseDelayMs * Math.pow(2, attempt - 1);
                console.log(`⏳ Retrying in ${delay}ms...`);
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }
    }

    console.error(`❌ Groq API failed after ${maxRetries} attempts: ${lastError?.message}`);
    return "🙏 Thank you for your response. Stay vigilant! 🛡️";
}

/**
 * Process a reply notification
 * @param notification - The notification containing the reply
 */
async function processReply(notification: MoltbookNotification): Promise<void> {
    try {
        const replyId = notification.id;
        const replyContent = notification.content;
        const postId = notification.postId;
        const parentCommentId = notification.parentCommentId || notification.commentId;
        
        // Validate required fields
        if (!replyId || !postId || !parentCommentId || !replyContent) {
            console.warn('⚠️ Invalid notification: missing required fields');
            return;
        }
        
        // Skip if already processed
        if (processedReplies.has(replyId)) {
            console.log(`⏭️ Skipping already processed reply: ${replyId}`);
            return;
        }
        
        // Safety Check 1: Strict check if the reply author is Namama itself (exact match only)
        const NAMAMA_USERNAME = (process.env.NAMAMA_USERNAME || 'namama_sovereign').toLowerCase().trim();
        const authorNameLower = notification.author.name.toLowerCase().trim();
        
        // Only block exact matches to prevent false positives (e.g., blocking "namama_fan")
        if (authorNameLower === NAMAMA_USERNAME) {
            console.log('⏭️ Skipping self-reply (Namama replying to own comment)');
            return;
        }
        
        // Safety Check 2: Check if the reply author is a bot (prevent bot loops)
        const isBotReply = moltbook.isBotAuthor(notification.author);
        if (isBotReply) {
            console.log('🤖 Skipping reply from another bot to prevent loop');
            processedReplies.add(replyId);
            // CRITICAL: Save immediately to persistent storage to prevent duplicate processing after restart
            await processedReplies.save();
            return;
        }
        
        console.log(`\n💬 Processing reply: "${sanitizeForLogging(replyContent).substring(0, 50)}..."`);
        console.log(`👤 Reply author: ${notification.author.name}`);
        
        // Get the original comment that was replied to
        // For now, we'll use a generic advisory message as context
        const originalCommentContext = "Digital Safety Advisory - Stay vigilant against scams and fraud";
        
        // Generate AI response for the reply
        const response = await generateReplyResponse(
            replyContent,
            originalCommentContext,
            isBotReply
        );
        
        // Post the reply - only mark as processed AFTER successful API call
        try {
            await moltbook.postReply(postId, parentCommentId, response);
            
            // Apply rate limit delay AFTER successful reply
            await rateLimitPost();
            
            // Mark as processed ONLY after successful reply
            processedReplies.add(replyId);
            await processedReplies.save(); // Immediate persist to prevent duplicates
            console.log('✅ Reply processed successfully');
        } catch (apiError) {
            // CRITICAL: Do NOT mark as processed if API call failed - allow retry
            console.error(`⚠️ Failed to post reply, will retry on next scan: ${apiError instanceof Error ? apiError.message : String(apiError)}`);
            throw apiError; // Re-throw to prevent marking as processed
        }
        
    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        console.error(`⚠️ Error processing reply ${notification.id}: ${message}`);
    }
}

/**
 * Process a single post
 * @param post - The Moltbook post to process
 */
async function processPost(post: MoltbookPost): Promise<void> {
    try {
        // Validate post object has required fields
        if (!post?.id || !post?.content) {
            console.warn(`⚠️ Invalid post object: missing id or content`);
            return;
        }
        // Skip if already processed
        if (processedIdsManager.has(post.id)) {
            console.log(`⏭️ Skipping already processed post: ${post.id}`);
            return;
        }

        console.log(`\n📝 Processing post: "${sanitizeForLogging(post.content).substring(0, 50)}..."`);
        
        // Check if it's a bot post
        const isBotPost = moltbook.isBotPost(post);
        const isCyberSecurity = moltbook.isCyberSecurityTopic(post);

        if (isBotPost) {
            console.log("🤖 Detected: Bot-to-Bot interaction");
        }
        if (isCyberSecurity) {
            console.log("🔐 Detected: Cyber Security topic");
        }

        // Extract risk patterns
        const riskPatterns = extractRiskPatterns(post);
        console.log(`⚡ Risk patterns detected: ${riskPatterns.join(', ') || 'none'}`);

        // Generate response
        const response = await generateAIResponse(
            post.content,
            isBotPost,
            isCyberSecurity,
            riskPatterns
        );

        // Post advisory comment
        await moltbook.postAdvisory(post.id, response);
        
        // Apply rate limit delay AFTER successful post (for next iteration)
        await rateLimitPost();
        
        // Mark as processed (atomic operation prevents race condition)
        if (processedIdsManager.addIfNotExists(post.id)) {
            console.log("✅ Advisory posted and post marked as processed");
        } else {
            console.log("⚠️ Post was already processed by another thread");
        }

    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        console.error(`⚠️ Error processing post ${post.id}: ${message}`);
    }
}

/**
 * Main agent loop - fetches and processes discussions
 */
async function scanAndProcess(): Promise<void> {
    console.log("\n" + "=".repeat(50));
    console.log("🔍 Starting Moltbook scan...");
    console.log("=".repeat(50));

    try {
        // Step 1: Check for new notifications/replies to Namama's comments
        console.log("\n📬 Checking for new reply notifications...");
        try {
            const notifications = await moltbook.getNotifications();
            
            if (notifications.length > 0) {
                console.log(`📬 Found ${notifications.length} notifications`);
                
                // Process replies (limit to prevent overwhelming)
                const REPLY_LIMIT = 5;
                const repliesToProcess = notifications.slice(0, REPLY_LIMIT);
                
                for (const notification of repliesToProcess) {
                    // Only process reply-type notifications
                    if (notification.type === 'reply' || notification.type === 'comment_reply') {
                        await processReply(notification);
                    }
                }
            } else {
                console.log("📬 No new notifications");
            }
        } catch (notifError) {
            console.warn('⚠️ Error fetching notifications:', notifError instanceof Error ? notifError.message : notifError);
            // Continue with post scanning even if notifications fail
        }
        
        // Step 2: Collect all posts from all queries, deduplicating by ID
        const allPosts: MoltbookPost[] = [];
        const seenIds = new Set<string>();
        
        // Search for posts matching our keywords
        for (const query of SEARCH_QUERIES) {
            try {
                console.log(`\n📡 Searching for: "${query}"`);
                
                const posts = await moltbook.fetchRecentDiscussions(query);
                
                if (posts.length === 0) {
                    console.log("  No posts found.");
                    continue;
                }

                console.log(`  Found ${posts.length} posts.`);

                // Add only unique posts (by ID) to avoid duplicate processing
                for (const post of posts) {
                    if (!seenIds.has(post.id)) {
                        seenIds.add(post.id);
                        allPosts.push(post);
                    }
                }
            } catch (queryError) {
                console.error(`⚠️ Error searching for "${query}":`, queryError instanceof Error ? queryError.message : queryError);
                continue; // Continue to next query instead of failing entire scan
            }
        }
        
        console.log(`\n📊 Total unique posts to process: ${allPosts.length}`);

        // Process only the top 5 most recent and relevant posts
        const BATCH_LIMIT = 5;
        const postsToProcess = allPosts.slice(0, BATCH_LIMIT);
        
        console.log(`📊 Processing top ${postsToProcess.length} posts`);

        // Process each unique post
        for (const post of postsToProcess) {
            await processPost(post);
        }

    } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        console.error(`⚠️ Scan Error: ${message}`);
    }

    console.log("\n✅ Scan cycle complete.");
}

/**
 * Start the Namama Autonomous Agent
 */

// Track shutdown state to prevent duplicate handler registration
let shutdownHandlersRegistered = false;

async function startAgent(): Promise<void> {
    console.log("🛡️ Namama Autonomous Agent: Groq Engine Active.");
    console.log("📍 Context: BharatOS Digital Infrastructure Layer.");
    console.log(`⏱️ Scan Interval: ${SCAN_INTERVAL_MS / 1000} seconds`);

    // Initialize the processed IDs manager (load persisted IDs)
    await initializeProcessedIdsManager();
    
    // Initialize the processed replies manager
    await processedReplies.init();
    console.log(`📂 Processed replies manager initialized with ${processedReplies.size} entries`);

    // UPGRADE 3: Initialize Persistent Guardian (load conversation history)
    await loadConversations();
    const stats = getGlobalStats();
    console.log(`🧠 Persistent Guardian: ${stats.totalUsers} users, ${stats.totalInteractions} interactions loaded`);

    // Schedule periodic cleanup of old conversations
    setInterval(async () => {
        await cleanupOldConversations();
    }, 24 * 60 * 60 * 1000); // Run cleanup once a day

    // Handle unhandled promise rejections (only register once)
    if (!shutdownHandlersRegistered) {
        shutdownHandlersRegistered = true;
        
        process.on('unhandledRejection', (reason) => {
            console.error("⚠️ Unhandled Rejection:", reason instanceof Error ? reason.message : reason);
            shutdown(); // Perform cleanup before exit
        });

        // Handle uncaught exceptions
        process.on('uncaughtException', (error) => {
            console.error("⚠️ Uncaught Exception:", error.message);
            shutdown(); // Perform cleanup before exit
        });
    }

    // Initial scan
    await scanAndProcess();

    // Post daily DSSL Introduction (proactive posting)
    await postIntroduction();

    // Set up recurring scan with proper error handling
    const runScan = async () => {
        try {
            await scanAndProcess();
        } catch (error) {
            console.error("⚠️ Scheduled scan error:", error instanceof Error ? error.message : error);
        }
    };

    // Initial recurring scan
    let scanIntervalId: NodeJS.Timeout | null = null;
    scanIntervalId = setInterval(runScan, SCAN_INTERVAL_MS);

    // Graceful shutdown: save processed IDs and clear intervals
    const shutdown = async () => {
        console.log("\n🛑 Shutting down gracefully...");
        if (scanIntervalId) clearInterval(scanIntervalId);
        
        try {
            processedIdsManager.close();
            processedReplies.close();
            // UPGRADE 3: Save conversation history on shutdown
            await saveConversations();
            console.log("✅ Processed IDs, replies, and conversations saved.");
        } catch (error) {
            console.error("⚠️ Failed to save processed data during shutdown:", error instanceof Error ? error.message : error);
        }
        
        // Force exit after timeout to ensure process terminates
        setTimeout(() => {
            console.log("⏰ Forcing process exit...");
            process.exit(0);
        }, 5000);
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
}

// Start the agent
startAgent().catch(console.error);
