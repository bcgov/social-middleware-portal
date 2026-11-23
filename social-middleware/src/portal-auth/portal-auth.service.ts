import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';
import * as jwt from 'jsonwebtoken';
import { PinoLogger } from 'nestjs-pino';
import { v4 as uuidv4 } from 'uuid';
import { SiebelApiService } from '../siebel/siebel-api.service';
import { TokenBlacklistService } from '../auth/services/token-blacklist.service';
import {
  PortalSessionPayload,
  PortalUserInfo,
} from './interfaces/portal-session-payload.interface';

export const PORTAL_SESSION_COOKIE = 'portal_session';
export const PORTAL_ID_TOKEN_COOKIE = 'portal_id_token';
export const PORTAL_OAUTH_COOKIE = 'portal_pkce';
const PORTAL_AUDIENCE = 'portal';
const SESSION_SECONDS = 4 * 60 * 60;

/**
 * Session handling for the separate portal. Deliberately independent of the
 * caregiver flow: no User records are written and no UserLoggedIn event is
 * emitted, so none of the caregiver login processes run.
 */
@Injectable()
export class PortalAuthService {
  constructor(
    private readonly configService: ConfigService,
    private readonly siebelApiService: SiebelApiService,
    private readonly tokenBlacklistService: TokenBlacklistService,
    private readonly logger: PinoLogger,
  ) {
    this.logger.setContext(PortalAuthService.name);
  }

  /** The portal is off unless PORTAL_FRONTEND_URL is set to a valid http(s) URL */
  get frontendUrl(): string | null {
    const raw = this.configService.get<string>('PORTAL_FRONTEND_URL')?.trim();
    if (!raw) return null;
    try {
      const { protocol } = new URL(raw);
      return ['http:', 'https:'].includes(protocol)
        ? raw.replace(/\/$/, '')
        : null;
    } catch {
      return null;
    }
  }

  get useKongOidc(): boolean {
    return this.configService.get<string>('USE_KONG_OIDC', 'true') === 'true';
  }

  private get secret(): string {
    return this.configService.get<string>('PORTAL_JWT_SECRET')!;
  }

  /** Validates the OIDC claims. Only what the portal needs: no address or birthdate. */
  parseUserInfo(raw: unknown): PortalUserInfo {
    if (!raw || typeof raw !== 'object') {
      throw new Error('Invalid user info');
    }
    const info = raw as Record<string, unknown>;
    if (typeof info.sub !== 'string' || !info.sub) {
      throw new Error("Invalid user info: missing 'sub'");
    }
    const str = (v: unknown): string => (typeof v === 'string' ? v : '');
    const name =
      str(info.name) ||
      [str(info.given_names), str(info.family_name)].filter(Boolean).join(' ');

    return { sub: info.sub, email: str(info.email), name };
  }

  parseKongUserInfoHeader(req: Request): PortalUserInfo {
    const header = req.headers['x-userinfo'];
    const value = Array.isArray(header) ? header[0] : header;
    if (!value) {
      throw new Error('X-Userinfo header missing');
    }
    const decoded = Buffer.from(value, 'base64').toString('utf-8');
    return this.parseUserInfo(JSON.parse(decoded));
  }

  /** Match the ICM contact by BCSC ID. A failed lookup never blocks login. */
  async matchContact(bcscId: string): Promise<string | undefined> {
    try {
      const contact = await this.siebelApiService.getContactByBcscId(bcscId);
      return contact?.Id || undefined;
    } catch (error) {
      this.logger.error({ error }, 'Portal: ICM contact match failed');
      return undefined;
    }
  }

  async createSession(userInfo: PortalUserInfo, res: Response): Promise<void> {
    const contactId = await this.matchContact(userInfo.sub);

    const token = jwt.sign(
      {
        sub: userInfo.sub,
        email: userInfo.email,
        name: userInfo.name,
        ...(contactId && { contactId }),
        jti: uuidv4(),
      },
      this.secret,
      { expiresIn: SESSION_SECONDS, audience: PORTAL_AUDIENCE },
    );

    res.cookie(
      PORTAL_SESSION_COOKIE,
      token,
      this.cookieOptions('strict', SESSION_SECONDS * 1000),
    );
    this.logger.info({ contactMatched: !!contactId }, 'Portal session created');
  }

  /** Returns the payload for a valid, non-revoked portal session, otherwise null */
  async verifySession(req: Request): Promise<PortalSessionPayload | null> {
    const token = (req.cookies as Record<string, string> | undefined)?.[
      PORTAL_SESSION_COOKIE
    ];
    if (!token) return null;

    try {
      const decoded = jwt.verify(token, this.secret, {
        audience: PORTAL_AUDIENCE,
      });
      if (!this.isPayload(decoded)) return null;
      if (await this.tokenBlacklistService.isBlacklisted(decoded.jti)) {
        return null;
      }
      return decoded;
    } catch {
      return null;
    }
  }

  async endSession(req: Request, res: Response): Promise<void> {
    const payload = await this.verifySession(req);
    if (payload?.exp) {
      const remaining = payload.exp - Math.floor(Date.now() / 1000);
      if (remaining > 0) {
        await this.tokenBlacklistService.blacklist(payload.jti, remaining);
      }
    }
    const options = this.cookieOptions('strict');
    res.clearCookie(PORTAL_SESSION_COOKIE, options);
    res.clearCookie(PORTAL_ID_TOKEN_COOKIE, options);
  }

  setIdTokenCookie(res: Response, idToken: string): void {
    res.cookie(
      PORTAL_ID_TOKEN_COOKIE,
      idToken,
      this.cookieOptions('strict', SESSION_SECONDS * 1000),
    );
  }

  // 'lax' is required for the short-lived OAuth cookies: the BCSC redirect
  // back to the callback is a cross-site navigation that 'strict' would drop.
  cookieOptions(sameSite: 'strict' | 'lax', maxAge?: number) {
    const cookieDomain =
      this.configService.get<string>('COOKIE_DOMAIN') || undefined;
    return {
      path: '/',
      httpOnly: true,
      secure:
        this.configService.get<string>('NODE_ENV') === 'production' ||
        !!this.frontendUrl?.startsWith('https://'),
      sameSite,
      ...(maxAge && { maxAge }),
      ...(cookieDomain && { domain: cookieDomain }),
    };
  }

  private isPayload(value: unknown): value is PortalSessionPayload {
    if (!value || typeof value !== 'object') return false;
    const v = value as Record<string, unknown>;
    return (
      typeof v.sub === 'string' &&
      typeof v.email === 'string' &&
      typeof v.name === 'string' &&
      typeof v.jti === 'string' &&
      (v.contactId === undefined || typeof v.contactId === 'string')
    );
  }
}
