import axios, { AxiosInstance, AxiosError } from 'axios';

/**
 * Moltbook API Client
 * Handles interactions with the Moltbook platform
 */
export class MoltbookClient {
    private client: AxiosInstance;
    private baseUrl: string;
    private maxRetries: number;
    private baseDelayMs: number;

    // Ensure baseUrl includes /api/v1 path
    private getBaseUrl(): string {
        const baseUrl = process.env.MOLTBOOK_API_URL || 'https://www.moltbook.com';
        
        // Validate domain to prevent redirect attacks
        try {
            const url = new URL(baseUrl);
            const allowedDomains = ['www.moltbook.com', 'moltbook.com', 'localhost'];
            const isLocalhost = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
            
            if (!isLocalhost && !allowedDomains.includes(url.hostname)) {
                throw new Error(`MOLTBOOK_API_URL domain '${url.hostname}' is not in the allowed list. Allowed: ${allowedDomains.join(', ')}`);
            }
        } catch (e) {
            throw new Error(`Invalid MOLTBOOK_API_URL: ${baseUrl}`);
        }
        
        return baseUrl.endsWith('/api/v1') ? baseUrl : `${baseUrl}/api/v1`;
    }

    constructor() {
        this.baseUrl = this.getBaseUrl();
        this.maxRetries = 3;
        this.baseDelayMs = 1000;
        
        // Validate API key at initialization
        const apiKey = process.env.MOLTBOOK_API_KEY?.trim() || '';
        if (!apiKey) {
            throw new Error("MOLTBOOK_API_KEY is missing in .env file!");
        }
        
        this.client = axios.create({
            baseURL: this.baseUrl,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            // International best practices: longer timeout for global latency
            timeout: 60000,
            // Retry configuration for resilience
            timeoutErrorMessage: 'Request timeout - please try again'
        });
    }

    /**
     * Execute a request with retry logic for transient failures
     * @param operation - Function that returns a promise
     * @returns Result of the operation
     */
    private async withRetry<T>(operation: () => Promise<T>): Promise<T> {
        let lastError: Error | null = null;
        
        for (let attempt = 1; attempt <= this.maxRetries; attempt++) {
            try {
                return await operation();
            } catch (error) {
                lastError = error instanceof Error ? error : new Error(String(error));
                
                // Determine if this error is retryable
                let isRetryable = true;
                let isRateLimited = false;
                
                if (error instanceof AxiosError) {
                    // Don't retry on 4xx errors (client errors) except 429 (rate limited)
                    if (error.response?.status && error.response.status >= 400 && error.response.status < 500 && error.response.status !== 429) {
                        isRetryable = false;
                    }
                    // Check for rate limiting
                    if (error.response?.status === 429) {
                        isRateLimited = true;
                    }
                    // Don't retry on network errors without response (DNS, timeout, etc.)
                    if (!error.response && (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT' || error.code === 'ENOTFOUND')) {
                        isRetryable = true; // Network errors ARE retryable
                    }
                } else {
                    // Non-Axios errors (DNS failures, timeouts, etc.) - retry by default
                    isRetryable = true;
                }
                
                // Don't retry if not retryable
                if (!isRetryable) {
                    throw lastError;
                }
                
                if (attempt < this.maxRetries) {
                    // Longer delay for rate limiting (429)
                    const delayMultiplier = isRateLimited ? 3 : 2;
                    const delay = this.baseDelayMs * Math.pow(delayMultiplier, attempt - 1);
                    console.log(`⚠️ Attempt ${attempt}/${this.maxRetries} failed${isRateLimited ? ' (rate limited)' : ''}, retrying in ${delay}ms...`);
                    await new Promise(resolve => setTimeout(resolve, delay));
                }
            }
        }
        
        throw lastError;
    }

    /**
     * Fetch recent discussions matching a query
     * @param query - Search keywords (e.g., 'UPI', 'scam', 'fraud', 'security')
     * @returns Array of discussion posts
     */
    async fetchRecentDiscussions(query: string): Promise<MoltbookPost[]> {
        return this.withRetry(async () => {
            if (process.env.DEBUG) {
                console.log(`[DEBUG] Search URL: ${this.baseUrl}/search`);
                console.log(`[DEBUG] Search params: q="${query}", limit=20, sort=recent`);
            }
            
            const response = await this.client.get('/search', {
                params: {
                    q: query,
                    limit: 20,
                    sort: 'recent',
                    type: 'posts' // यह सुनिश्चित करता है कि केवल पोस्ट्स ही वापस आएं
                }
            });
            
            // API 'results' फील्ड का उपयोग करता है, 'posts' का नहीं
            const results = response.data.results;
            if (!Array.isArray(results)) {
                console.warn('⚠️ Unexpected API response: results is not an array');
                return [];
            }
            
            // API के snake_case (created_at) को आपके camelCase (createdAt) में मैप करें
            return results.map((post: any) => ({
                ...post,
                createdAt: post.created_at || new Date().toISOString()
            }));
        });
    }

    /**
     * Post Namama's advisory response as a comment
     * @param postId - The ID of the post to comment on
     * @param content - The advisory content to post
     * @returns The created comment object
     */
    async postAdvisory(postId: string, content: string): Promise<MoltbookComment> {
        // Input validation
        if (!postId || postId.trim().length === 0) {
            throw new Error("Post ID cannot be empty");
        }
        if (!content || content.trim().length === 0) {
            throw new Error("Content cannot be empty");
        }
        
        // Gracefully truncate content if it exceeds maximum length
        const MAX_CONTENT_LENGTH = 1000;
        let finalContent = content;
        if (content.length > MAX_CONTENT_LENGTH) {
            finalContent = content.substring(0, MAX_CONTENT_LENGTH - 3) + "...";
            console.warn(`⚠️ Content truncated from ${content.length} to ${finalContent.length} characters`);
        }

        return this.withRetry(async () => {
            // Send only content - author is managed via token
            const response = await this.client.post(`/posts/${postId}/comments`, {
                content: finalContent
            });
            return response.data;
        });
    }

    /**
     * Create a new discussion post
     * @param title - The title of the post
     * @param content - The main content of the post
     * @returns The created post object
     */
    async createPost(title: string, content: string): Promise<any> {
        // Input validation
        if (!title || title.trim().length === 0) {
            throw new Error("Title cannot be empty");
        }
        if (!content || content.trim().length === 0) {
            throw new Error("Content cannot be empty");
        }
        
        // Input sanitization: encode HTML entities to preserve content while preventing XSS
        const sanitizedTitle = title
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;')
            .trim();
        const sanitizedContent = content
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;')
            .trim();
        
        // सुरक्षा के लिए कंटेंट को 2000 अक्षरों तक सीमित (Truncate) करें
        const MAX_POST_LENGTH = 2000;
        const finalContent = sanitizedContent.length > MAX_POST_LENGTH 
            ? sanitizedContent.substring(0, MAX_POST_LENGTH - 3) + "..." 
            : sanitizedContent;
        const finalTitle = sanitizedTitle.length > 200 
            ? sanitizedTitle.substring(0, 197) + "..." 
            : sanitizedTitle;

        return this.withRetry(async () => {
            // Debug logging for troubleshooting 400 errors
            const shouldDebug = (process.env.DEBUG || process.env.VERBOSE) && process.env.NODE_ENV !== 'production';
            if (shouldDebug) {
                console.log('[DEBUG] createPost payload:', JSON.stringify({
                    title: finalTitle,
                    content: finalContent,
                    submolt: process.env.MOLTBOOK_SUBMOLT_ID || "dssl",
                    submolt_name: process.env.MOLTBOOK_SUBMOLT_NAME || "DSSL Safety Layer"
                }));
            }
            
            // Send title, content with Submolt (community/group) info
            const response = await this.client.post('/posts', {
                title: finalTitle,
                content: finalContent,
                // Use environment variable for Submolt ID, default to 'dssl'
                submolt: process.env.MOLTBOOK_SUBMOLT_ID || "dssl",
                submolt_name: process.env.MOLTBOOK_SUBMOLT_NAME || "DSSL Safety Layer"
            });
            return response.data;
        });
    }

    /**
     * Check if a post is from a bot account
     * @param post - The Moltbook post to check
     * @returns true if the author is a bot
     */
    isBotPost(post: MoltbookPost): boolean {
        if (!post.author || !post.author.name) return false;
        return post.author.isBot === true || 
               post.author.type === 'bot' ||
               post.author.name.toLowerCase().includes('bot');
    }

    /**
     * Check if a post is about cyber security
     * @param post - The Moltbook post to check
     * @returns true if the topic is cyber security related
     */
    isCyberSecurityTopic(post: MoltbookPost): boolean {
        const keywords = [
            'cyber security', 'cybersecurity', 'hacking', 'phishing',
            'malware', 'ransomware', 'data breach', 'privacy',
            'digital safety', 'online fraud', 'cybercrime'
        ];
        
        const content = (post.content + ' ' + (post.tags || []).join(' ')).toLowerCase();
        return keywords.some(keyword => content.includes(keyword));
    }

    /**
     * Check if an author is a bot
     * @param author - The author object to check
     * @returns true if the author is a bot
     */
    isBotAuthor(author: MoltbookAuthor | undefined): boolean {
        if (!author) return false;
        return author.isBot === true || 
               author.type === 'bot' ||
               author.name.toLowerCase().includes('bot');
    }

    /**
     * Fetch notifications - checks for replies to namama_sovereign's comments
     * @returns Array of reply notifications
     */
    async getNotifications(): Promise<MoltbookNotification[]> {
        return this.withRetry(async () => {
            const response = await this.client.get('/notifications', {
                params: {
                    type: 'replies', // Only fetch reply notifications
                    limit: 20
                }
            });
            
            const results = response.data.results || response.data.notifications || [];
            if (!Array.isArray(results)) {
                console.warn('⚠️ Unexpected API response: notifications is not an array');
                return [];
            }
            
            return results.map((notification: any) => ({
                id: notification.id,
                type: notification.type,
                postId: notification.post_id || notification.postId,
                commentId: notification.comment_id || notification.commentId,
                parentCommentId: notification.parent_comment_id || notification.parentCommentId,
                content: notification.content || notification.reply?.content || '',
                author: notification.author || notification.reply?.author || {
                    id: notification.user_id || '',
                    name: notification.user_name || 'Unknown'
                },
                createdAt: notification.created_at || notification.createdAt || new Date().toISOString()
            }));
        });
    }

    /**
     * Fetch comments on a specific post
     * @param postId - The ID of the post to fetch comments from
     * @returns Array of comments
     */
    async getComments(postId: string): Promise<MoltbookComment[]> {
        if (!postId || postId.trim().length === 0) {
            throw new Error("Post ID cannot be empty");
        }
        
        return this.withRetry(async () => {
            const response = await this.client.get(`/posts/${postId}/comments`, {
                params: {
                    limit: 50
                }
            });
            
            const results = response.data.results || response.data.comments || [];
            if (!Array.isArray(results)) {
                console.warn('⚠️ Unexpected API response: comments is not an array');
                return [];
            }
            
            return results.map((comment: any) => ({
                id: comment.id,
                postId: comment.post_id || postId,
                content: comment.content || '',
                author: comment.author?.name || comment.author_name || 'Unknown',
                authorId: comment.author?.id || comment.author_id || '',
                createdAt: comment.created_at || comment.createdAt || new Date().toISOString()
            }));
        });
    }

    /**
     * Post a reply to a comment
     * @param postId - The ID of the post containing the comment
     * @param parentCommentId - The ID of the comment to reply to
     * @param content - The reply content
     * @returns The created reply object
     */
    async postReply(postId: string, parentCommentId: string, content: string): Promise<MoltbookComment> {
        if (!postId || postId.trim().length === 0) {
            throw new Error("Post ID cannot be empty");
        }
        if (!parentCommentId || parentCommentId.trim().length === 0) {
            throw new Error("Parent comment ID cannot be empty");
        }
        if (!content || content.trim().length === 0) {
            throw new Error("Content cannot be empty");
        }
        
        // Truncate content if too long
        const MAX_CONTENT_LENGTH = 1000;
        let finalContent = content;
        if (content.length > MAX_CONTENT_LENGTH) {
            finalContent = content.substring(0, MAX_CONTENT_LENGTH - 3) + "...";
            console.warn(`⚠️ Content truncated from ${content.length} to ${finalContent.length} characters`);
        }

        return this.withRetry(async () => {
            const response = await this.client.post(`/posts/${postId}/comments/${parentCommentId}/replies`, {
                content: finalContent
            });
            return response.data;
        });
    }
}

/**
 * Moltbook Post interface
 */
export interface MoltbookPost {
    id: string;
    content: string;
    author: {
        id: string;
        name: string;
        isBot?: boolean;
        type?: string;
    };
    tags?: string[];
    createdAt: string;
    engagement?: {
        likes: number;
        comments: number;
    };
}

/**
 * Moltbook Comment interface
 */
export interface MoltbookComment {
    id: string;
    postId: string;
    content: string;
    author: string;
    authorId?: string;
    createdAt: string;
}

/**
 * Moltbook Author interface
 */
export interface MoltbookAuthor {
    id: string;
    name: string;
    isBot?: boolean;
    type?: string;
}

/**
 * Moltbook Notification interface
 */
export interface MoltbookNotification {
    id: string;
    type: string;
    postId: string;
    commentId?: string;
    parentCommentId?: string;
    content: string;
    author: {
        id: string;
        name: string;
        isBot?: boolean;
        type?: string;
    };
    createdAt: string;
}
