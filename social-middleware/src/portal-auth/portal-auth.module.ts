import { Module } from '@nestjs/common';
import { TokenBlacklistModule } from '../auth/services/token-blacklist.module';
import { SiebelModule } from '../siebel/siebel.module';
import { PortalAuthController } from './portal-auth.controller';
import { PortalAuthService } from './portal-auth.service';
import { PortalBcscOAuthService } from './portal-bcsc-oauth.service';
import { PortalSessionGuard } from './portal-session.guard';

@Module({
  imports: [SiebelModule, TokenBlacklistModule],
  controllers: [PortalAuthController],
  providers: [PortalAuthService, PortalBcscOAuthService, PortalSessionGuard],
  exports: [PortalAuthService, PortalSessionGuard],
})
export class PortalAuthModule {}
