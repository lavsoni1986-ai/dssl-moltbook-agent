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
            'automated_social_engineering',       // NEW: AI-powered social engineering
            // ============ NEW ADVANCED FRAUD PATTERNS ============
            'money_mule_detection',               // Money mule recruitment
            'upi_fraud_signature',                // UPI QR/link fraud
            'otp_scam_detected',                  // OTP theft
            'ai_scam_pattern',                     // AI-generated fraud
            'crypto_scam_signature',               // Cryptocurrency fraud
            'impersonation_scam',                  // Authority impersonation
            'vishing_attempt',                     // Voice phishing
            'smishing_detected',                   // SMS phishing
            'deepfake_audio_fraud',                // AI voice cloning
            'job_scam_detection',                  // Fake job offers
            'part_time_fraud_pattern'              // Part-time work scams
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

/**
 * Get specific fraud type and prevention advice based on detected patterns
 * @param patterns - Array of detected risk patterns
 * @returns Object with fraud type name and prevention advice
 */
export function getFraudAdvisory(patterns: string[]): { fraudType: string; prevention: string } | null {
    const fraudAdvisories: Record<string, { fraudType: string; prevention: string }> = {
        // Money Mule
        'money_mule_detection': {
            fraudType: 'Money Mule Recruitment',
            prevention: 'Never let others use your bank account to transfer money. Report suspicious requests to your bank immediately. Money mules are often recruited through social media with promises of easy commissions.'
        },
        // UPI Fraud
        'upi_fraud_signature': {
            fraudType: 'UPI Payment Fraud',
            prevention: 'Never scan unknown QR codes or click on UPI payment links from strangers. Verify all payment requests independently. Use only official UPI apps.'
        },
        // OTP Scam
        'otp_scam_detected': {
            fraudType: 'OTP Theft Scam',
            prevention: 'NEVER share your OTP, PIN, or password with anyone - even bank staff will never ask for these. Hang up suspicious calls claiming to be from banks.'
        },
        // AI Scams
        'ai_scam_pattern': {
            fraudType: 'AI-Generated Fraud',
            prevention: 'Be wary of videos or voice calls from unknown numbers - AI can impersonate anyone. Verify through independent channels before trusting urgent requests.'
        },
        // Crypto Scam
        'crypto_scam_signature': {
            fraudType: 'Cryptocurrency Investment Scam',
            prevention: 'Beware of guaranteed returns or "double your money" crypto schemes. Never invest based on social media tips. Verify exchanges before use.'
        },
        // Impersonation
        'impersonation_scam': {
            fraudType: 'Authority Impersonation Scam',
            prevention: 'Banks, police, and government agencies NEVER ask for account details or OTPs via phone. Hang up and call the official number directly.'
        },
        // Vishing
        'vishing_attempt': {
            fraudType: 'Voice Phishing (Vishing)',
            prevention: 'Never verify account details through incoming calls. Legitimate organizations never pressure you for immediate action. Verify by calling official numbers.'
        },
        // Smishing
        'smishing_detected': {
            fraudType: 'SMS Phishing (Smishing)',
            prevention: 'Never click links in suspicious SMS messages. Delete messages asking for OTP, bank details, or KYC updates. Verify directly through official apps.'
        },
        // Deepfake Audio
        'deepfake_audio_fraud': {
            fraudType: 'Deepfake Audio Fraud',
            prevention: 'If you receive an urgent voice request from a family member, verify through a different channel. AI voice cloning is increasingly common.'
        },
        // Job Scam
        'job_scam_detection': {
            fraudType: 'Fake Job Offer Scam',
            prevention: 'Legitimate jobs never require upfront payment or deposit. Research companies thoroughly. Never share personal banking details for job applications.'
        },
        // Part-time Fraud
        'part_time_fraud_pattern': {
            fraudType: 'Part-Time Work Scam',
            prevention: 'Be cautious of "easy money" part-time jobs. Never pay to join a job or share OTPs for "verification". Research opportunities thoroughly.'
        },
        // Legacy patterns
        'high_velocity_upi': {
            fraudType: 'UPI Financial Fraud',
            prevention: 'Never share OTPs or PINs. Verify payment requests carefully before confirming.'
        },
        'known_fraud_pattern': {
            fraudType: 'Lottery/Prize Scam',
            prevention: 'You cannot win a lottery you did not enter. Delete such messages immediately.'
        },
        'new_domain_link': {
            fraudType: 'Suspicious Link/Phishing',
            prevention: 'Never click on unknown links. Verify URLs carefully - scammers use similar-looking domains.'
        }
    };

    // Find first matching advisory
    for (const pattern of patterns) {
        if (fraudAdvisories[pattern]) {
            return fraudAdvisories[pattern];
        }
    }
    return null;
}
