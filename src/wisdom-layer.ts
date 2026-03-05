// Wisdom Layer - Adding Wisdom Over Intelligence
// Namama: The World's First Sovereign Global Safety Agent

export interface WisdomQuote {
    id: string;
    text: string;
    source: string;
    context: string;
}

// Curated wisdom from global sources - organized by theme
export const WISDOM_QUOTES: Record<string, WisdomQuote[]> = {
    // Awareness and Vigilance
    awareness: [
        {
            id: 'awareness_1',
            text: 'The fool doth think he is wise, but the wise knows himself to be a fool.',
            source: 'William Shakespeare',
            context: 'Digital Safety'
        },
        {
            id: 'awareness_2',
            text: 'Knowledge is knowing a tomato is a fruit. Wisdom is not putting it in a fruit salad.',
            source: 'Anonymous',
            context: 'Understanding digital risks vs believing every online offer'
        },
        {
            id: 'awareness_3',
            text: 'In the middle of difficulty lies opportunity.',
            source: 'Albert Einstein',
            context: 'Turning scam awareness into digital empowerment'
        }
    ],
    
    // Trust and Skepticism
    trust: [
        {
            id: 'trust_1',
            text: 'Trust, but verify.',
            source: 'Russian Proverb',
            context: 'Verify all digital requests independently'
        },
        {
            id: 'trust_2',
            text: 'The safest way to double your money is to fold it over and put it in your pocket.',
            source: 'Hubert Bancroft',
            context: 'No guaranteed returns exist - especially online'
        },
        {
            id: 'trust_3',
            text: 'A honest man is the only free man.',
            source: 'Thomas Jefferson',
            context: 'Being honest about what you dont know protects you'
        }
    ],
    
    // Patience and Impulse
    patience: [
        {
            id: 'patience_1',
            text: 'He who can wait for what he desires takes the course not to be misled by the hopes of him who is impatient.',
            source: 'Ovid',
            context: 'Urgency tactics in scams - pause before acting'
        },
        {
            id: 'patience_2',
            text: 'Patience is the companion of wisdom.',
            source: 'Saint Augustine',
            context: 'Taking time to verify protects you'
        },
        {
            id: 'patience_3',
            text: 'Do not haste to pay back a promise in the same day.',
            source: 'Mahatma Gandhi',
            context: 'Never act on urgent demands - legitimate requests wait'
        }
    ],
    
    // Digital Sovereignty
    sovereignty: [
        {
            id: 'sov_1',
            text: 'Give a man a fish and you feed him for a day; teach a man to fish and you feed him for a lifetime.',
            source: 'Chinese Proverb',
            context: 'DSSL philosophy: teach digital safety, not just block threats'
        },
        {
            id: 'sov_2',
            text: 'Digital Swaraj is not just about access, but about autonomy.',
            source: 'Digital Philosophy',
            context: 'Your data, your decisions, your sovereignty'
        },
        {
            id: 'sov_3',
            text: 'The best protection is self-protection through awareness.',
            source: 'Ancient Wisdom',
            context: 'Empowering citizens to protect themselves'
        }
    ],
    
    // Common Scam Themes
    greed: [
        {
            id: 'greed_1',
            text: 'The love of money is the root of all evil.',
            source: '1 Timothy 6:10',
            context: 'Greed drives most financial scams'
        },
        {
            id: 'greed_2',
            text: 'If it is too good to be true, it probably is.',
            source: 'Anonymous',
            context: 'The golden rule of digital safety'
        },
        {
            id: 'greed_3',
            text: 'A person who is greedy is always in want.',
            source: 'Classical Proverb',
            context: 'Scammers exploit desire for easy money'
        }
    ],
    
    // Fear and Courage
    fear: [
        {
            id: 'fear_1',
            text: 'Courage is not the absence of fear, but action in spite of it.',
            source: 'Mark Twain',
            context: 'Being cautious is being courageous online'
        },
        {
            id: 'fear_2',
            text: 'Fear is a darkroom where negatives develop.',
            source: 'Usman Khasim',
            context: 'Scammers use fear - recognize it and act wisely'
        },
        {
            id: 'fear_3',
            text: 'The only thing we have to fear is fear itself.',
            source: 'Franklin D. Roosevelt',
            context: 'Dont let scammer threats paralyze your judgment'
        }
    ],
    
    // Community and Help
    community: [
        {
            id: 'comm_1',
            text: 'Alone we can do so little; together we can do so much.',
            source: 'Helen Keller',
            context: 'DSSL: Global community protecting each other'
        },
        {
            id: 'comm_2',
            text: 'Unity is strength.',
            source: 'Latin Proverb',
            context: 'Sharing awareness protects the community'
        },
        {
            id: 'comm_3',
            text: 'It takes a village to raise a child, and a global community to secure the digital world.',
            source: 'Digital Wisdom',
            context: 'Digital safety is a collective responsibility'
        }
    ]
};

// Theme keywords for matching
export const THEME_KEYWORDS: Record<string, string[]> = {
    trust: ['trust', 'believe', 'real', 'fake', 'verify', 'legitimate', 'official', 'real', 'genuine'],
    patience: ['urgent', 'immediately', 'hurry', 'quick', 'fast', 'limited time', 'act now', 'deadline'],
    greed: ['free', 'win', 'prize', 'lottery', 'money', 'rich', 'million', 'billion', 'double', 'guaranteed', 'return'],
    fear: ['block', 'suspend', 'arrest', 'police', 'court', 'legal', 'action', 'bank', 'account', 'close', 'frozen'],
    awareness: ['learn', 'know', 'understand', 'aware', 'teach', 'education', 'safety', 'protect', 'secure'],
    sovereignty: ['right', 'own', 'control', 'choice', 'freedom', 'consent', 'my data', 'privacy', 'swaraj'],
    community: ['share', 'help', 'together', 'community', 'everyone', 'all', 'people', 'citizen', 'global']
};

/**
 * Get appropriate wisdom quote based on detected risk patterns or message context
 * @param riskPatterns - Array of detected risk patterns
 * @param userMessage - Original user message for context matching
 * @returns Selected wisdom quote
 */
export function getWisdomQuote(riskPatterns: string[] = [], userMessage: string = ''): string {
    const lowerMessage = userMessage.toLowerCase();
    const allPatterns = [...riskPatterns, lowerMessage].join(' ');
    
    // Determine dominant theme
    let selectedTheme = 'awareness'; // Default theme
    
    const themeScores: Record<string, number> = {};
    
    for (const [theme, keywords] of Object.entries(THEME_KEYWORDS)) {
        let score = 0;
        for (const keyword of keywords) {
            if (allPatterns.includes(keyword)) {
                score++;
            }
        }
        themeScores[theme] = score;
    }
    
    // Find highest scoring theme
    let maxScore = 0;
    for (const [theme, score] of Object.entries(themeScores)) {
        if (score > maxScore) {
            maxScore = score;
            selectedTheme = theme;
        }
    }
    
    // Get quotes for theme
    const quotes = WISDOM_QUOTES[selectedTheme] || WISDOM_QUOTES['awareness'];
    
    if (!quotes || quotes.length === 0) {
        return '';
    }
    
    // Select quote based on time of day for variety
    const hour = new Date().getHours();
    const index = hour % quotes.length;
    const quote = quotes[index];
    
    if (!quote) {
        return '';
    }
    
    return `\n\n💫 **Wisdom for the Journey:**\n"${quote.text}"\n— *${quote.source}*\n_${quote.context}_`;
}

/**
 * Format wisdom for embedding in response
 * @param quote - The wisdom quote to embed
 * @returns Formatted wisdom text
 */
export function embedWisdom(quote: string): string {
    return quote;
}

/**
 * Generate contextual wisdom based on user's interaction history
 * @param userEngagementLevel - How many times user has interacted with Namama
 * @param riskLevel - Current risk level
 * @returns Tailored wisdom message
 */
export function getContextualWisdom(userEngagementLevel: number, riskLevel: string): string {
    // New users get foundational wisdom
    if (userEngagementLevel === 0) {
        return `\n\n🌟 **Welcome to Digital Sovereignty!**\nYour safety is your right. I am here to empower you with knowledge, not to make decisions for you. Ask me anything about staying safe online.`;
    }
    
    // Returning users get deeper wisdom
    if (userEngagementLevel < 3) {
        return `\n\n🔮 **Remember:** In the digital world, your awareness is your superpower. Every question you ask makes you safer.`;
    }
    
    // Engaged users - deeper philosophy
    if (riskLevel === 'HIGH') {
        return `\n\n🛡️ **Digital Wisdom:** The scammer wants you to act NOW. Your power is in PAUSING. Take a breath, verify independently, then decide.`;
    }
    
    return `\n\n🌏 **Global Citizen Wisdom:** You are now part of a global community protecting each other. Share this knowledge—every person you awareness is a victory for humanity.`;
}
