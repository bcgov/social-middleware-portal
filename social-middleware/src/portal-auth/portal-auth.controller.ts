import {
  Controller,
  Get,
  HttpException,
  HttpStatus,
  NotFoundException,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { Request, Response } from 'express';
import { PinoLogger } from 'nestjs-pino';
import {
  PortalBcscOAuthService,
  PortalPkceData,
} from './portal-bcsc-oauth.service';
import {
  PORTAL_ID_TOKEN_COOKIE,
  PORTAL_OAUTH_COOKIE,
  PortalAuthService,
} from './portal-auth.service';
import {
  PortalAuthenticatedRequest,
  PortalSessionGuard,
} from './portal-session.guard';

/**
 * Login for the separate portal. Mirrors /auth/* but is independent of it:
 * it does not create caregiver users or trigger caregiver sync processes.
 *
 * Kong mode (USE_KONG_OIDC=true): Kong must protect /portal/auth/login and
 * /portal/auth/callback with its OIDC plugin and forward X-Userinfo.
 * Direct mode (USE_KONG_OIDC=false): redirects to BCSC; the redirect URI
 * {MIDDLEWARE_URL}/portal/auth/callback must be registered with BCSC.
 */
@ApiTags('Portal Authentication')
@Controller('portal/auth')
export class PortalAuthController {
  constructor(
    private readonly portalAuthService: PortalAuthService,
    private readonly bcscOAuthService: PortalBcscOAuthService,
    private readonly configService: ConfigService,
    private readonly logger: PinoLogger,
  ) {
    this.logger.setContext(PortalAuthController.name);
  }

  private requireFrontendUrl(): string {
    const url = this.portalAuthService.frontendUrl;
    if (!url) {
      // Portal login is disabled until PORTAL_FRONTEND_URL is configured
      throw new NotFoundException();
    }
    return url;
  }

  private redirectWithError(
    res: Response,
    frontendUrl: string,
    errorCode: string,
  ): void {
    this.logger.error({ errorCode }, 'Portal login redirecting with error');
    res.redirect(`${frontendUrl}/login?error=${errorCode}`);
  }

  @Get('login')
  @ApiOperation({ summary: 'Portal login (Kong OIDC or direct BCSC OAuth)' })
  async login(@Req() req: Request, @Res() res: Response): Promise<void> {
    const frontendUrl = this.requireFrontendUrl();

    if (this.portalAuthService.useKongOidc) {
      await this.completeKongLogin(req, res, frontendUrl, 'not_authenticated');
      return;
    }

    const { url, pkce } = this.bcscOAuthService.buildAuthorization();
    res.cookie(
      PORTAL_OAUTH_COOKIE,
      JSON.stringify(pkce),
      this.portalAuthService.cookieOptions('lax', 10 * 60 * 1000),
    );
    res.redirect(url);
  }

  @Get('callback')
  @ApiOperation({ summary: 'Portal OIDC callback' })
  async callback(@Req() req: Request, @Res() res: Response): Promise<void> {
    const frontendUrl = this.requireFrontendUrl();

    if (this.portalAuthService.useKongOidc) {
      await this.completeKongLogin(req, res, frontendUrl, 'oidc_failed');
      return;
    }

    try {
      const code = typeof req.query.code === 'string' ? req.query.code : null;
      const state =
        typeof req.query.state === 'string' ? req.query.state : null;
      const pkce = this.readPkceCookie(req);
      res.clearCookie(PORTAL_OAUTH_COOKIE, { path: '/' });

      if (!pkce || !state || state !== pkce.state) {
        this.redirectWithError(res, frontendUrl, 'state_mismatch');
        return;
      }
      if (!code) {
        this.redirectWithError(res, frontendUrl, 'no_code');
        return;
      }

      const tokens = await this.bcscOAuthService.exchangeCode(
        code,
        pkce.codeVerifier,
      );
      const userInfo = this.portalAuthService.parseUserInfo(
        await this.bcscOAuthService.getUserInfo(tokens.access_token),
      );

      await this.portalAuthService.createSession(userInfo, res);
      this.portalAuthService.setIdTokenCookie(res, tokens.id_token);
      res.redirect(`${frontendUrl}/auth/callback`);
    } catch (err) {
      this.logger.error({ err }, 'Portal OAuth callback failed');
      this.redirectWithError(res, frontendUrl, 'auth_processing_failed');
    }
  }

  @Get('status')
  @ApiOperation({ summary: 'Check portal authentication status' })
  async status(@Req() req: Request) {
    this.requireFrontendUrl();
    const payload = await this.portalAuthService.verifySession(req);
    if (!payload) {
      throw new HttpException(
        { error: 'Not authenticated' },
        HttpStatus.UNAUTHORIZED,
      );
    }

    return {
      user: { id: payload.sub, email: payload.email, name: payload.name },
      contactMatched: !!payload.contactId,
      expiresAt: payload.exp ? payload.exp * 1000 : 0,
    };
  }

  @Get('me')
  @UseGuards(PortalSessionGuard)
  @ApiOperation({ summary: 'Current portal user and ICM contact match' })
  me(@Req() req: PortalAuthenticatedRequest) {
    const user = req.portalUser!;
    return {
      id: user.sub,
      email: user.email,
      name: user.name,
      contactId: user.contactId ?? null,
    };
  }

  @Get('logout')
  @ApiOperation({ summary: 'End the portal session' })
  async logout(@Req() req: Request, @Res() res: Response): Promise<void> {
    const frontendUrl = this.requireFrontendUrl();
    const idToken = (req.cookies as Record<string, string> | undefined)?.[
      PORTAL_ID_TOKEN_COOKIE
    ];
    await this.portalAuthService.endSession(req, res);

    const postLogout = encodeURIComponent(`${frontendUrl}/login`);

    if (this.portalAuthService.useKongOidc) {
      const middlewareUrl = this.configService
        .get<string>('MIDDLEWARE_URL', 'http://localhost:3001')
        .trim();
      res.redirect(
        `${middlewareUrl}/logout?post_logout_redirect_uri=${postLogout}`,
      );
      return;
    }

    const authority = this.configService.get<string>('BCSC_AUTHORITY');
    let logoutUrl = `${authority}/protocol/openid-connect/logout?post_logout_redirect_uri=${postLogout}`;
    if (idToken) {
      logoutUrl += `&id_token_hint=${encodeURIComponent(idToken)}`;
    }
    res.redirect(logoutUrl);
  }

  private async completeKongLogin(
    req: Request,
    res: Response,
    frontendUrl: string,
    missingHeaderError: string,
  ): Promise<void> {
    if (!req.headers['x-userinfo']) {
      this.redirectWithError(res, frontendUrl, missingHeaderError);
      return;
    }
    try {
      const userInfo = this.portalAuthService.parseKongUserInfoHeader(req);
      await this.portalAuthService.createSession(userInfo, res);
      res.redirect(`${frontendUrl}/auth/callback`);
    } catch (err) {
      this.logger.error({ err }, 'Portal Kong OIDC processing failed');
      this.redirectWithError(res, frontendUrl, 'auth_processing_failed');
    }
  }

  private readPkceCookie(req: Request): PortalPkceData | null {
    const raw = (req.cookies as Record<string, string> | undefined)?.[
      PORTAL_OAUTH_COOKIE
    ];
    if (!raw) return null;
    try {
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      return typeof parsed.state === 'string' &&
        typeof parsed.codeVerifier === 'string'
        ? { state: parsed.state, codeVerifier: parsed.codeVerifier }
        : null;
    } catch {
      return null;
    }
  }
}
