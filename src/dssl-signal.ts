// DSSL Signal Standardization - Global Cyber-Watch Format
// Namama: The World's First Sovereign Global Safety Agent

export interface DSSL_Signal {
    // Signal Identification
    signalId: string;           // Unique signal identifier
    version: string;           // DSSL protocol version
    timestamp: string;         // ISO 8601 timestamp
    
    // Threat Classification
    threatCategory: ThreatCategory;
    threatSeverity: ThreatSeverity;
    threatRegions: string[];   // Affected regions
    
    // Detection Details
    patterns: string[];        // Matched patterns
    confidence: number;        // 0-100 confidence score
    
    // Risk Assessment
    riskLevel: RiskLevel;
    affectedPlatforms: string[];
    
    // Mitigation
    prevention: string;
    resources: string[];
    
    // Metadata
    source: string;            // Detection source
    dsslPhilosophy: string;
}

export type ThreatCategory = 
    | 'phishing' 
    | 'crypto_fraud' 
    | 'social_engineering' 
    | 'impersonation' 
    | 'financial_fraud' 
    | 'ai_generated_threat'
    | 'data_breach'
    | 'identity_theft'
    | 'cyberbullying'
    | 'other';

export type ThreatSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type RiskLevel = 'HIGH' | 'MEDIUM' | 'LOW';

/**
 * Generate a DSSL Signal for a detected threat
 * @param threatType - Type of threat detected
 * @param patterns - Matched patterns
 * @param regions - Affected regions
 * @param platform - Platform where detected
 * @returns Standardized DSSL Signal
 */
export function generateDSSL_Signal(
    threatType: ThreatCategory,
    patterns: string[],
    regions: string[],
    platform: string,
    riskLevel: RiskLevel,
    prevention: string
): DSSL_Signal {
    const severityMap: Record<RiskLevel, ThreatSeverity> = {
        'HIGH': 'HIGH',
        'MEDIUM': 'MEDIUM',
        'LOW': 'LOW'
    };
    
    const signalId = generateSignalId();
    
    return {
        signalId,
        version: '1.0.0',
        timestamp: new Date().toISOString(),
        threatCategory: threatType,
        threatSeverity: severityMap[riskLevel],
        threatRegions: regions,
        patterns,
        confidence: calculateConfidence(patterns),
        riskLevel,
        affectedPlatforms: [platform],
        prevention,
        resources: getResources(threatType),
        source: 'DSSL-Namama',
        dsslPhilosophy: 'Universal Upstream Prevention - protecting digital citizens globally'
    };
}

/**
 * Generate unique signal ID
 * @returns Unique signal identifier
 */
function generateSignalId(): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 8);
    return `DSSL-${timestamp}-${random}`.toUpperCase();
}

/**
 * Calculate confidence based on matched patterns
 * @param patterns - Array of matched patterns
 * @returns Confidence score 0-100
 */
function calculateConfidence(patterns: string[]): number {
    if (patterns.length === 0) return 10;
    if (patterns.length === 1) return 40;
    if (patterns.length === 2) return 65;
    if (patterns.length >= 3) return 85;
    return 50;
}

/**
 * Get relevant resources for threat type
 * @param threatType - Type of threat
 * @returns Array of resource URLs
 */
function getResources(threatType: ThreatCategory): string[] {
    const resources: Record<ThreatCategory, string[]> = {
        phishing: [
            'https://www.cybersafe.gov.phishing',
            'https://www.antiphishing.org'
        ],
        crypto_fraud: [
            'https://www.coingecko.com/scam',
            'https://www.sec.gov/crypto'
        ],
        social_engineering: [
            'https://www.consumerfinance.gov/ scam',
            'https://www.ic3.gov'
        ],
        impersonation: [
            'https://www.impersonation.gov',
            'https://www.police.gov.in'
        ],
        financial_fraud: [
            'https://www.rbi.org.in/safety',
            'https://www.consumerfinance.gov'
        ],
        ai_generated_threat: [
            'https://www.deepfakeawareness.org',
            'https://www.nist.gov/ai'
        ],
        data_breach: [
            'https://www.haveibeenpwned.com',
            'https://www.privacy.gov.au'
        ],
        identity_theft: [
            'https://www.identity.gov',
            'https://www.annualcreditreport.com'
        ],
        cyberbullying: [
            'https://www.cyberbullying.org',
            'https://www.stopbullying.gov'
        ],
        other: [
            'https://www.dssl.global/resources'
        ]
    };
    
    return resources[threatType] || resources.other;
}

/**
 * Format DSSL Signal for display in responses
 * @param signal - The DSSL signal to format
 * @returns Formatted markdown string
 */
export function formatDSSL_Signal(signal: DSSL_Signal): string {
    const severityEmoji: Record<ThreatSeverity, string> = {
        CRITICAL: '🔴',
        HIGH: '🟠',
        MEDIUM: '🟡',
        LOW: '🟢',
        INFO: 'ℹ️'
    };
    
    const categoryEmoji: Record<ThreatCategory, string> = {
        phishing: '🎣',
        crypto_fraud: '₿',
        social_engineering: '🎭',
        impersonation: '🎭',
        financial_fraud: '💳',
        ai_generated_threat: '🤖',
        data_breach: '🔓',
        identity_theft: '👤',
        cyberbullying: '💬',
        other: '⚠️'
    };
    
    return `
╔══════════════════════════════════════════════════════════════╗
║                    🌐 DSSL GLOBAL SIGNAL 🌐                   ║
╠══════════════════════════════════════════════════════════════╣
║ Signal ID: ${signal.signalId}
║ Version: ${signal.version} | Timestamp: ${signal.timestamp}
╠══════════════════════════════════════════════════════════════╣
║ ${categoryEmoji[signal.threatCategory]} Category: ${signal.threatCategory.toUpperCase()}
║ ${severityEmoji[signal.threatSeverity]} Severity: ${signal.threatSeverity}
║ 🌍 Regions: ${signal.threatRegions.join(', ')}
║ 📊 Confidence: ${signal.confidence}%
╠══════════════════════════════════════════════════════════════╣
║ 🔍 Patterns: ${signal.patterns.join(', ')}
║ ⚠️ Risk Level: ${signal.riskLevel}
║ 💻 Platforms: ${signal.affectedPlatforms.join(', ')}
╠══════════════════════════════════════════════════════════════╣
║ 🛡️ Prevention:
║ ${wrapText(signal.prevention, 58).join('\n║ ')}
╠══════════════════════════════════════════════════════════════╣
║ 📚 Resources: ${signal.resources.join(', ')}
║ 💡 Philosophy: ${signal.dsslPhilosophy}
╚══════════════════════════════════════════════════════════════╝
`.trim();
}

/**
 * Wrap text to fit in signal box
 * @param text - Text to wrap
 * @param maxWidth - Maximum line width
 * @returns Array of wrapped lines
 */
function wrapText(text: string, maxWidth: number): string[] {
    const words = text.split(' ');
    const lines: string[] = [];
    let currentLine = '';
    
    for (const word of words) {
        if ((currentLine + ' ' + word).trim().length <= maxWidth) {
            currentLine = (currentLine + ' ' + word).trim();
        } else {
            if (currentLine) lines.push(currentLine);
            currentLine = word;
        }
    }
    if (currentLine) lines.push(currentLine);
    
    return lines;
}

/**
 * Export signal to JSON format (for API responses)
 * @param signal - The DSSL signal
 * @returns JSON string
 */
export function exportSignalToJSON(signal: DSSL_Signal): string {
    return JSON.stringify(signal, null, 2);
}

/**
 * Validate signal format
 * @param signal - Signal to validate
 * @returns true if valid
 */
export function validateSignal(signal: DSSL_Signal): boolean {
    return !!(
        signal.signalId &&
        signal.version &&
        signal.timestamp &&
        signal.threatCategory &&
        signal.threatSeverity &&
        signal.riskLevel &&
        signal.patterns.length > 0
    );
}
