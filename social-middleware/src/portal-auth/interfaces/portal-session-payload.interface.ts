export interface PortalUserInfo {
  sub: string;
  email: string;
  name: string;
}

export interface PortalSessionPayload {
  sub: string;
  email: string;
  name: string;
  // ICM contact row ID; undefined when no ICM contact matched the BCSC ID
  contactId?: string;
  jti: string;
  iat?: number;
  exp?: number;
}
