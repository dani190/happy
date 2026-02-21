import * as privacyKit from "privacy-kit";
import { log } from "@/utils/log";

interface TokenCacheEntry {
    userId: string;
    extras?: any;
    cachedAt: number;
    expiresAt: number;
}

const MAX_CACHE_SIZE = 10000;
const TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const CLEANUP_INTERVAL_MS = 60 * 60 * 1000; // 1 hour

interface AuthTokens {
    generator: Awaited<ReturnType<typeof privacyKit.createPersistentTokenGenerator>>;
    verifier: Awaited<ReturnType<typeof privacyKit.createPersistentTokenVerifier>>;
    githubVerifier: Awaited<ReturnType<typeof privacyKit.createEphemeralTokenVerifier>>;
    githubGenerator: Awaited<ReturnType<typeof privacyKit.createEphemeralTokenGenerator>>;
}

class AuthModule {
    private tokenCache = new Map<string, TokenCacheEntry>();
    private tokens: AuthTokens | null = null;
    private cleanupTimer: ReturnType<typeof setInterval> | null = null;

    async init(): Promise<void> {
        if (this.tokens) {
            return; // Already initialized
        }

        // Validate master secret
        if (!process.env.HANDY_MASTER_SECRET) {
            throw new Error('HANDY_MASTER_SECRET environment variable is required');
        }
        if (process.env.HANDY_MASTER_SECRET.length < 32) {
            throw new Error('HANDY_MASTER_SECRET must be at least 32 characters');
        }

        log({ module: 'auth' }, 'Initializing auth module...');

        // Start periodic cache cleanup
        this.cleanupTimer = setInterval(() => this.cleanup(), CLEANUP_INTERVAL_MS);

        const generator = await privacyKit.createPersistentTokenGenerator({
            service: 'handy',
            seed: process.env.HANDY_MASTER_SECRET!
        });

        
        const verifier = await privacyKit.createPersistentTokenVerifier({
            service: 'handy',
            publicKey: Uint8Array.from(generator.publicKey)
        });
        
        const githubGenerator = await privacyKit.createEphemeralTokenGenerator({
            service: 'github-happy',
            seed: process.env.HANDY_MASTER_SECRET!,
            ttl: 5 * 60 * 1000 // 5 minutes
        });

        const githubVerifier = await privacyKit.createEphemeralTokenVerifier({
            service: 'github-happy',
            publicKey: Uint8Array.from(githubGenerator.publicKey),
        });


        this.tokens = { generator, verifier, githubVerifier, githubGenerator };
        
        log({ module: 'auth' }, 'Auth module initialized');
    }
    
    async createToken(userId: string, extras?: any): Promise<string> {
        if (!this.tokens) {
            throw new Error('Auth module not initialized');
        }
        
        const payload: any = { user: userId };
        if (extras) {
            payload.extras = extras;
        }
        
        const token = await this.tokens.generator.new(payload);
        
        // Cache the token with TTL
        this.cacheToken(token, userId, extras);

        return token;
    }
    
    async verifyToken(token: string): Promise<{ userId: string; extras?: any } | null> {
        // Check cache first
        const cached = this.tokenCache.get(token);
        if (cached) {
            return {
                userId: cached.userId,
                extras: cached.extras
            };
        }
        
        // Cache miss - verify token
        if (!this.tokens) {
            throw new Error('Auth module not initialized');
        }
        
        try {
            const verified = await this.tokens.verifier.verify(token);
            if (!verified) {
                return null;
            }
            
            const userId = verified.user as string;
            const extras = verified.extras;
            
            // Cache the result with TTL
            this.cacheToken(token, userId, extras);
            
            return { userId, extras };
            
        } catch (error) {
            log({ module: 'auth', level: 'error' }, `Token verification failed: ${error}`);
            return null;
        }
    }
    
    invalidateUserTokens(userId: string): void {
        // Remove all tokens for a specific user
        // This is expensive but rarely needed
        for (const [token, entry] of this.tokenCache.entries()) {
            if (entry.userId === userId) {
                this.tokenCache.delete(token);
            }
        }
        
        log({ module: 'auth' }, `Invalidated tokens for user: ${userId}`);
    }
    
    invalidateToken(token: string): void {
        this.tokenCache.delete(token);
    }
    
    getCacheStats(): { size: number; oldestEntry: number | null } {
        if (this.tokenCache.size === 0) {
            return { size: 0, oldestEntry: null };
        }
        
        let oldest = Date.now();
        for (const entry of this.tokenCache.values()) {
            if (entry.cachedAt < oldest) {
                oldest = entry.cachedAt;
            }
        }
        
        return {
            size: this.tokenCache.size,
            oldestEntry: oldest
        };
    }
    
    async createGithubToken(userId: string): Promise<string> {
        if (!this.tokens) {
            throw new Error('Auth module not initialized');
        }
        
        const payload = { user: userId, purpose: 'github-oauth' };
        const token = await this.tokens.githubGenerator.new(payload);
        
        return token;
    }

    async verifyGithubToken(token: string): Promise<{ userId: string } | null> {
        if (!this.tokens) {
            throw new Error('Auth module not initialized');
        }
        
        try {
            const verified = await this.tokens.githubVerifier.verify(token);
            if (!verified) {
                return null;
            }
            
            return { userId: verified.user as string };
        } catch (error) {
            log({ module: 'auth', level: 'error' }, `GitHub token verification failed: ${error}`);
            return null;
        }
    }

    private cacheToken(token: string, userId: string, extras?: any): void {
        // Evict expired entries if cache is full
        if (this.tokenCache.size >= MAX_CACHE_SIZE) {
            this.cleanup();
        }
        // If still full after cleanup, evict oldest entry
        if (this.tokenCache.size >= MAX_CACHE_SIZE) {
            let oldestKey: string | null = null;
            let oldestTime = Infinity;
            for (const [key, entry] of this.tokenCache.entries()) {
                if (entry.cachedAt < oldestTime) {
                    oldestTime = entry.cachedAt;
                    oldestKey = key;
                }
            }
            if (oldestKey) {
                this.tokenCache.delete(oldestKey);
            }
        }
        this.tokenCache.set(token, {
            userId,
            extras,
            cachedAt: Date.now(),
            expiresAt: Date.now() + TOKEN_TTL_MS,
        });
    }

    cleanup(): void {
        const now = Date.now();
        let evicted = 0;
        for (const [token, entry] of this.tokenCache.entries()) {
            if (entry.expiresAt < now) {
                this.tokenCache.delete(token);
                evicted++;
            }
        }
        log({ module: 'auth' }, `Token cache cleanup: evicted ${evicted}, remaining ${this.tokenCache.size}`);
    }
}

// Global instance
export const auth = new AuthModule();