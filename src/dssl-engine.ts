// DSSL Knowledge Base - Universal Digital Safety Framework
// Supports global cyber-threat detection and upstream prevention

export const DSSL_KNOWLEDGE_BASE = {
    philosophy: "Universal Upstream Prevention - stopping digital harm before it happens, anywhere in the world.",
    legalDisclaimer: "This platform provides risk indicators only and does not confirm criminal activity.",
    rules: [
        "Advisory-only: No direct actions taken on behalf of users.",
        "Probabilistic: Risks are pattern-based, not absolute facts.",
        "Non-punitive: No labeling as 'scammer' or 'criminal'.",
        "Global: Operates as Digital Public Infrastructure for cross-border digital trust."
    ],
    globalContext: [
        "DSSL serves as sovereign infrastructure for universal digital safety.",
        "Cross-border digital trust requires upstream prevention, not reactive measures.",
        "Like DNS or BGP, DSSL is essential public infrastructure."
    ]
};

export function calculateRiskSignal(patterns: string[]): 'HIGH' | 'MEDIUM' | 'LOW' {
    // Universal risk indicators for global cyber-threats
    const riskIndicators = {
        // HIGH: Critical threats requiring immediate attention
        HIGH: [
            'high_velocity_upi', 
            'unverified_bulk_sms', 
            'known_fraud_pattern',
            'synthetic_identity_match',           // NEW: Synthetic identity fraud detection
            'cross_platform_scam_signature',      // NEW: Multi-platform scam patterns
            'automated_social_engineering'       // NEW: AI-powered social engineering
        ],
        // MEDIUM: Suspicious patterns warranting caution
        MEDIUM: [
            'new_domain_link', 
            'unusual_request_time', 
            'mismatched_display_name',
            'urgency_tactic_detected',          // NEW: Psychological manipulation tactics
            'obfuscated_url',                   // NEW: Hidden/masked URLs
            'unusual_cross_border_request'       // NEW: Atypical international transactions
        ],
        // LOW: Standard activity
        LOW: [
            'standard_transaction', 
            'verified_merchant_signal'
        ]
    };

    if (patterns.some(p => riskIndicators.HIGH.includes(p))) return 'HIGH';
    if (patterns.some(p => riskIndicators.MEDIUM.includes(p))) return 'MEDIUM';
    return 'LOW';
}
