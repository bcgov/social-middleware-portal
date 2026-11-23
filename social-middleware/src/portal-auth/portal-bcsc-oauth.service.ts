import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';
import * as crypto from 'crypto';
import { PinoLogger } from 'nestjs-pino';

export interface PortalPkceData {
  state: string;
  codeVerifier: string;
}

interface BcscTokenResponse {
  access_token: string;
  id_token: string;
}

/**
 * Direct BCSC OAuth for the portal (USE_KONG_OIDC=false).
 * Stateless: PKCE data travels in a cookie, and the redirect URI is the
 * portal callback, so it never touches the caregiver BcscOAuthService.
 */
@Injectable()
export class PortalBcscOAuthService {
  constructor(
    private readonly configService: ConfigService,
    private readonly logger: PinoLogger,
  ) {
    this.logger.setContext(PortalBcscOAuthService.name);
  }

  private get redirectUri(): string {
    const middlewareUrl = this.configService.get<string>('MIDDLEWARE_URL')!;
    return `${middlewareUrl}/portal/auth/callback`;
  }

  private get clientId(): string {
    return this.configService.get<string>('PORTAL_BCSC_CLIENT_ID')!;
  }

  private get clientSecret(): string {
    return this.configService.get<string>('PORTAL_BCSC_CLIENT_SECRET')!;
  }

  private get authority(): string {
    return this.configService.get<string>('BCSC_AUTHORITY')!;
  }

  buildAuthorization(): { url: string; pkce: PortalPkceData } {
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64url');
    const state = crypto.randomBytes(16).toString('base64url');

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: 'openid email profile',
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    return {
      url: `${this.authority}/authorize?${params.toString()}`,
      pkce: { state, codeVerifier },
    };
  }

  async exchangeCode(
    code: string,
    codeVerifier: string,
  ): Promise<BcscTokenResponse> {
    try {
      const params = new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: this.clientId,
        client_secret: this.clientSecret,
        code,
        redirect_uri: this.redirectUri,
        code_verifier: codeVerifier,
      });

      const response = await axios.post<BcscTokenResponse>(
        `${this.authority}/protocol/openid-connect/token`,
        params.toString(),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
      );
      return response.data;
    } catch (error: unknown) {
      this.logger.error(
        { status: axios.isAxiosError(error) ? error.response?.status : null },
        'Portal: failed to exchange authorization code',
      );
      throw new Error('Failed to authenticate with BCSC');
    }
  }

  async getUserInfo(accessToken: string): Promise<unknown> {
    try {
      const response = await axios.get<unknown>(
        `${this.authority}/protocol/openid-connect/userinfo`,
        { headers: { Authorization: `Bearer ${accessToken}` } },
      );
      return response.data;
    } catch (error: unknown) {
      this.logger.error(
        { status: axios.isAxiosError(error) ? error.response?.status : null },
        'Portal: failed to fetch BCSC user info',
      );
      throw new Error('Failed to fetch user information from BCSC');
    }
  }
}
