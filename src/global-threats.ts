// Global Threat Synthesis - Universal Scam Pattern Detection
// Namama: The World's First Sovereign Global Safety Agent

export interface GlobalThreatPattern {
    id: string;
    name: string;
    category: 'phishing' | 'crypto' | 'social_engineering' | 'impersonation' | 'financial' | 'ai_generated';
    regions: string[];
    description: string;
    prevention: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
}

// Global Threat Knowledge Base - Synthesized from worldwide fraud patterns
export const GLOBAL_THREAT_SYNTHESIS: GlobalThreatPattern[] = [
    // ==================== CRITICAL GLOBAL THREATS ====================
    {
        id: 'global_phishing_drainer',
        name: 'Global Phishing Drainer',
        category: 'phishing',
        regions: ['GLOBAL', 'INDIA', 'USA', 'EU', 'APAC'],
        description: 'Sophisticated phishing attacks that drain accounts across borders using fake login pages',
        prevention: 'Always verify URLs manually. Enable 2FA. Never click links in unexpected emails.',
        severity: 'CRITICAL'
    },
    {
        id: 'crypto_drainer',
        name: 'Crypto Wallet Drainer',
        category: 'crypto',
        regions: ['GLOBAL'],
        description: 'Malicious smart contracts and fake token approvals that drain crypto wallets',
        prevention: 'Never approve unknown token contracts. Review all permissions carefully. Use hardware wallets.',
        severity: 'CRITICAL'
    },
    {
        id: 'ai_deepfake_extortion',
        name: 'AI Deepfake Extortion',
        category: 'ai_generated',
        regions: ['GLOBAL'],
        description: 'AI-generated deepfake videos used for blackmail and extortion',
        prevention: 'Be cautious with video calls from unknown numbers. Verify through independent channels.',
        severity: 'CRITICAL'
    },
    {
        id: 'job_human_trafficking',
        name: 'Job Portal Trafficking',
        category: 'social_engineering',
        regions: ['INDIA', 'SOUTHEAST_ASIA', 'AFRICA'],
        description: 'Fake job offers leading to human trafficking and scam centers',
        prevention: 'Research companies thoroughly. Never pay upfront fees. Verify job offers through official channels.',
        severity: 'CRITICAL'
    },
    // ==================== HIGH SEVERITY THREATS ====================
    {
        id: 'romance_scam',
        name: 'Romance/Investment Scam',
        category: 'social_engineering',
        regions: ['GLOBAL', 'WESTERN_AFRICA', 'SOUTH_ASIA'],
        description: 'Long-term relationship building leading to investment or emergency money requests',
        prevention: 'Never send money to someone you have not met in person. Video call before trusting.',
        severity: 'HIGH'
    },
    {
        id: 'tech_support_scam',
        name: 'Tech Support Impersonation',
        category: 'impersonation',
        regions: ['USA', 'INDIA', 'EU'],
        description: 'Fake tech support calls or pop-ups claiming compromised systems',
        prevention: 'Microsoft/Apple never calls you first. Hang up and call official support numbers.',
        severity: 'HIGH'
    },
    {
        id: 'business_email_compromise',
        name: 'Business Email Compromise (BEC)',
        category: 'financial',
        regions: ['GLOBAL'],
        description: 'Fake invoices or CEO fraud targeting businesses',
        prevention: 'Verify payment requests via separate communication channel. Use multi-factor approval.',
        severity: 'HIGH'
    },
    {
        id: 'fake_crypto_exchange',
        name: 'Fake Crypto Exchange',
        category: 'crypto',
        regions: ['GLOBAL', 'KOREA', 'JAPAN', 'TURKEY'],
        description: 'Fake exchanges that disappear with users funds',
        prevention: 'Use only regulated exchanges. Research exchange reviews. Never keep large amounts on exchanges.',
        severity: 'HIGH'
    },
    // ==================== MEDIUM SEVERITY THREATS ====================
    {
        id: 'social_media_giveaway',
        name: 'Fake Giveaway Scam',
        category: 'social_engineering',
        regions: ['GLOBAL'],
        description: 'Fake crypto or prize giveaways requiring deposit to claim',
        prevention: 'Legitimate giveaways never require deposit. If it sounds too good to be true, it is.',
        severity: 'MEDIUM'
    },
    {
        id: 'Fake_loan_app',
        name: 'Predatory Loan App',
        category: 'financial',
        regions: ['INDIA', 'AFRICA', 'SOUTHEAST_ASIA'],
        description: 'Illegal lending apps with predatory terms and harassment',
        prevention: 'Only use RBI/NBFC regulated lenders. Check app legitimacy before installing.',
        severity: 'MEDIUM'
    },
    {
        id: 'matrimony_fraud',
        name: 'Matrimony Site Fraud',
        category: 'social_engineering',
        regions: ['INDIA', 'SOUTH_ASIA'],
        description: 'Fake profiles on marriage websites seeking money',
        prevention: 'Verify profiles through multiple sources. Never send money to romantic interests.',
        severity: 'MEDIUM'
    },
    {
        id: 'government_imposter',
        name: 'Government Imposter Scam',
        category: 'impersonation',
        regions: ['INDIA', 'USA', 'UK'],
        description: 'Calls claiming to be from police, RBI, or tax department',
        prevention: 'Government agencies never demand immediate payment or OTPs via phone.',
        severity: 'MEDIUM'
    }
];

// Map category to display emoji
export const CATEGORY_EMOJI: Record<string, string> = {
    phishing: '🎣',
    crypto: '₿',
    social_engineering: '🎭',
    impersonation: '🎭',
    financial: '💳',
    ai_generated: '🤖'
};

// Map severity to emoji
export const SEVERITY_INDICATOR: Record<string, string> = {
    CRITICAL: '🔴',
    HIGH: '🟠',
    MEDIUM: '🟡'
};

/**
 * Detect global threats from message content
 * @param message - User message to analyze
 * @returns Array of matched global threat patterns
 */
export function detectGlobalThreats(message: string): GlobalThreatPattern[] {
    const lowerMessage = message.toLowerCase();
    const matchedThreats: GlobalThreatPattern[] = [];
    
    for (const threat of GLOBAL_THREAT_SYNTHESIS) {
        // Simple keyword matching - can be enhanced with ML
        const keywords = threat.name.toLowerCase().split(' ');
        const descriptionWords = threat.description.toLowerCase().split(' ');
        
        const hasMatch = [...keywords, ...descriptionWords].some(word => 
            word.length > 4 && lowerMessage.includes(word)
        );
        
        if (hasMatch) {
            matchedThreats.push(threat);
        }
    }
    
    // Sort by severity
    const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2 };
    matchedThreats.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
    
    return matchedThreats;
}

/**
 * Get threat summary for display
 * @param threats - Array of detected threats
 * @returns Formatted threat summary
 */
export function getThreatSummary(threats: GlobalThreatPattern[]): string {
    if (threats.length === 0) return '';
    
    const summary = threats.map(t => 
        `${SEVERITY_INDICATOR[t.severity]} **${t.name}** (${t.regions.join(', ')})`
    ).join('\n');
    
    return `\n\n🌐 **Global Threat Synthesis:**\n${summary}`;
}
