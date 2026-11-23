import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Request } from 'express';
import { PortalSessionPayload } from './interfaces/portal-session-payload.interface';
import { PortalAuthService } from './portal-auth.service';

export interface PortalAuthenticatedRequest extends Request {
  portalUser?: PortalSessionPayload;
}

/** Guard for portal endpoints. Only accepts the portal_session cookie. */
@Injectable()
export class PortalSessionGuard implements CanActivate {
  constructor(private readonly portalAuthService: PortalAuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context
      .switchToHttp()
      .getRequest<PortalAuthenticatedRequest>();

    const payload = await this.portalAuthService.verifySession(request);
    if (!payload) return false;

    request.portalUser = payload;
    return true;
  }
}
