// Persistent Guardian - Contextual Memory for User Conversations
// Namama: The World's First Sovereign Global Safety Agent

import * as fs from 'fs';
import * as path from 'path';

export interface UserConversation {
    userId: string;
    userName: string;
    posts: UserPost[];
    lastInteraction: number;
    engagementLevel: number;
    warningsGiven: string[];
    wisdomShared: string[];
}

export interface UserPost {
    postId: string;
    timestamp: number;
    content: string;
    threatPatterns: string[];
    riskLevel: string;
    namamaResponse: string;
}

export interface ConversationStore {
    conversations: Record<string, UserConversation>;
    lastCleanup: number;
}

// Configuration
const CONVERSATION_FILE = process.env.CONVERSATION_STORE_FILE || 'data/conversations.json';
const MAX_CONVERSATIONS = parseInt(process.env.MAX_CACHED_CONVERSATIONS || '1000', 10);
const CONVERSATION_RETENTION_DAYS = parseInt(process.env.CONVERSATION_RETENTION_DAYS || '90', 10);
const MAX_POSTS_PER_USER = parseInt(process.env.MAX_POSTS_PER_USER || '50', 10);

let conversationStore: ConversationStore = {
    conversations: {},
    lastCleanup: Date.now()
};

// Ensure data directory exists
const DATA_DIR = 'data';
try {
    if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
    }
} catch (error) {
    console.error('Failed to create data directory:', error);
}

/**
 * Load conversations from persistent storage
 */
export async function loadConversations(): Promise<void> {
    try {
        if (fs.existsSync(CONVERSATION_FILE)) {
            const data = await fs.promises.readFile(CONVERSATION_FILE, 'utf-8');
            const parsed = JSON.parse(data);
            if (parsed.conversations) {
                conversationStore = parsed;
                console.log(`📂 Loaded ${Object.keys(conversationStore.conversations).length} user conversations`);
            }
        }
    } catch (error) {
        console.warn('⚠️ Failed to load conversations:', error instanceof Error ? error.message : error);
    }
}

/**
 * Save conversations to persistent storage
 */
export async function saveConversations(): Promise<void> {
    try {
        await fs.promises.writeFile(CONVERSATION_FILE, JSON.stringify(conversationStore, null, 2), 'utf-8');
    } catch (error) {
        console.error('❌ Failed to save conversations:', error instanceof Error ? error.message : error);
    }
}

/**
 * Get or create user conversation
 * @param userId - Unique user identifier
 * @param userName - User's display name
 * @returns User conversation object
 */
export function getOrCreateConversation(userId: string, userName: string): UserConversation {
    if (!conversationStore.conversations[userId]) {
        conversationStore.conversations[userId] = {
            userId,
            userName,
            posts: [],
            lastInteraction: Date.now(),
            engagementLevel: 0,
            warningsGiven: [],
            wisdomShared: []
        };
    }
    
    const conversation = conversationStore.conversations[userId];
    conversation.lastInteraction = Date.now();
    
    return conversation;
}

/**
 * Record a user interaction
 * @param userId - User identifier
 * @param userName - User display name
 * @param post - The post details
 * @param threatPatterns - Detected threat patterns
 * @param riskLevel - Risk level
 * @param namamaResponse - Namama's response
 */
export function recordInteraction(
    userId: string,
    userName: string,
    postId: string,
    content: string,
    threatPatterns: string[],
    riskLevel: string,
    namamaResponse: string
): void {
    const conversation = getOrCreateConversation(userId, userName);
    
    // Add new post
    conversation.posts.push({
        postId,
        timestamp: Date.now(),
        content: content.substring(0, 500), // Truncate for storage
        threatPatterns,
        riskLevel,
        namamaResponse: namamaResponse.substring(0, 500)
    });
    
    // Limit posts per user
    if (conversation.posts.length > MAX_POSTS_PER_USER) {
        conversation.posts = conversation.posts.slice(-MAX_POSTS_PER_USER);
    }
    
    // Increment engagement level
    conversation.engagementLevel++;
    
    // Record warnings if any
    if (riskLevel !== 'LOW') {
        conversation.warningsGiven.push(`${riskLevel}: ${threatPatterns.join(', ')}`);
    }
}

/**
 * Get user's engagement level
 * @param userId - User identifier
 * @returns Engagement level (0+)
 */
export function getUserEngagementLevel(userId: string): number {
    const conversation = conversationStore.conversations[userId];
    return conversation?.engagementLevel || 0;
}

/**
 * Get user's conversation history
 * @param userId - User identifier
 * @returns User's conversation history
 */
export function getUserHistory(userId: string): UserPost[] {
    const conversation = conversationStore.conversations[userId];
    return conversation?.posts || [];
}

/**
 * Check if user has been warned about specific threat patterns before
 * @param userId - User identifier
 * @param pattern - Threat pattern to check
 * @returns true if user has been warned about this pattern before
 */
export function hasBeenWarnedAbout(userId: string, pattern: string): boolean {
    const conversation = conversationStore.conversations[userId];
    if (!conversation) return false;
    
    return conversation.warningsGiven.some(warning => warning.includes(pattern));
}

/**
 * Get context summary for user (for contextual responses)
 * @param userId - User identifier
 * @returns Summary of user's interaction history
 */
export function getUserContext(userId: string): string {
    const conversation = conversationStore.conversations[userId];
    if (!conversation || conversation.posts.length === 0) {
        return 'new_user';
    }
    
    const lastPost = conversation.posts[conversation.posts.length - 1];
    
    if (!lastPost) {
        return 'new_user';
    }
    
    const uniqueThreats = new Set(conversation.posts.flatMap(p => p.threatPatterns));
    
    return `engaged_${conversation.engagementLevel}_risks_${uniqueThreats.size}_last_${lastPost.riskLevel}`;
}

/**
 * Clean up old conversations
 */
export async function cleanupOldConversations(): Promise<number> {
    const now = Date.now();
    const retentionMs = CONVERSATION_RETENTION_DAYS * 24 * 60 * 60 * 1000;
    let cleanedCount = 0;
    
    for (const [userId, conversation] of Object.entries(conversationStore.conversations)) {
        if (now - conversation.lastInteraction > retentionMs) {
            delete conversationStore.conversations[userId];
            cleanedCount++;
        }
    }
    
    // Also limit total conversations
    const userIds = Object.keys(conversationStore.conversations);
    if (userIds.length > MAX_CONVERSATIONS) {
        // Sort by last interaction and remove oldest
        userIds.sort((a, b) => 
            (conversationStore.conversations[b]?.lastInteraction || 0) - 
            (conversationStore.conversations[a]?.lastInteraction || 0)
        );
        
        const toRemove = userIds.slice(MAX_CONVERSATIONS);
        for (const userId of toRemove) {
            delete conversationStore.conversations[userId];
            cleanedCount++;
        }
    }
    
    if (cleanedCount > 0) {
        conversationStore.lastCleanup = now;
        await saveConversations();
        console.log(`🧹 Cleaned up ${cleanedCount} old conversations`);
    }
    
    return cleanedCount;
}

/**
 * Get global statistics
 * @returns Statistics about recorded conversations
 */
export function getGlobalStats(): {
    totalUsers: number;
    totalInteractions: number;
    highRiskUsers: number;
    averageEngagement: number;
} {
    const conversations = Object.values(conversationStore.conversations);
    
    if (conversations.length === 0) {
        return {
            totalUsers: 0,
            totalInteractions: 0,
            highRiskUsers: 0,
            averageEngagement: 0
        };
    }
    
    const totalInteractions = conversations.reduce((sum, c) => sum + c.posts.length, 0);
    const highRiskUsers = conversations.filter(c => 
        c.posts.some(p => p.riskLevel === 'HIGH')
    ).length;
    const averageEngagement = totalInteractions / conversations.length;
    
    return {
        totalUsers: conversations.length,
        totalInteractions,
        highRiskUsers,
        averageEngagement: Math.round(averageEngagement * 10) / 10
    };
}

/**
 * Generate contextual response prefix based on user history
 * @param userId - User identifier
 * @param userName - User's name
 * @returns Contextual greeting based on history
 */
export function getContextualGreeting(userId: string, userName: string): string {
    const engagementLevel = getUserEngagementLevel(userId);
    const history = getUserHistory(userId);
    
    if (engagementLevel === 0) {
        return `Namama welcomes you, ${userName}! 🌟`;
    }
    
    if (engagementLevel < 3) {
        return `Welcome back, ${userName}! It's good to see you again. 👋`;
    }
    
    // Check if last interaction was recent (within 24 hours)
    const lastPost = history[history.length - 1];
    if (lastPost && Date.now() - lastPost.timestamp < 24 * 60 * 60 * 1000) {
        return `${userName}! Good to connect again. Let's continue building your digital safety. 🛡️`;
    }
    
    return `Welcome back, ${userName}! Your digital safety journey continues. 📚`;
}
