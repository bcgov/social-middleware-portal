import { Request, Response } from 'express';
import * as jwt from 'jsonwebtoken';
import { PortalAuthService } from './portal-auth.service';

const PORTAL_SECRET = 'portal-test-secret';
const CAREGIVER_SECRET = 'caregiver-test-secret';

describe('PortalAuthService', () => {
  const env: Record<string, string> = {
    PORTAL_JWT_SECRET: PORTAL_SECRET,
    JWT_SECRET: CAREGIVER_SECRET,
    NODE_ENV: 'test',
    PORTAL_FRONTEND_URL: 'http://localhost:5174/',
  };
  const configService = {
    get: jest.fn((key: string, def?: string) => env[key] ?? def),
  };
  const siebel = { getContactByBcscId: jest.fn() };
  const blacklist = {
    isBlacklisted: jest.fn().mockResolvedValue(false),
    blacklist: jest.fn().mockResolvedValue(undefined),
  };
  const logger = { setContext: jest.fn(), info: jest.fn(), error: jest.fn() };

  let service: PortalAuthService;

  const res = () =>
    ({ cookie: jest.fn(), clearCookie: jest.fn() }) as unknown as Response & {
      cookie: jest.Mock;
      clearCookie: jest.Mock;
    };
  const reqWith = (cookies: Record<string, string>) =>
    ({ cookies, headers: {} }) as unknown as Request;
  const user = { sub: 'bcsc-1', email: 'a@b.ca', name: 'A B' };

  beforeEach(() => {
    jest.clearAllMocks();
    blacklist.isBlacklisted.mockResolvedValue(false);
    service = new PortalAuthService(
      configService as never,
      siebel as never,
      blacklist as never,
      logger as never,
    );
  });

  it('is disabled without PORTAL_FRONTEND_URL and trims a trailing slash otherwise', () => {
    expect(service.frontendUrl).toBe('http://localhost:5174');
    delete env.PORTAL_FRONTEND_URL;
    expect(service.frontendUrl).toBeNull();
    env.PORTAL_FRONTEND_URL = 'http://localhost:5174/';
  });

  it('accepts users with no address or birthdate', () => {
    expect(
      service.parseUserInfo({ sub: 's', given_names: 'A', family_name: 'B' }),
    ).toEqual({ sub: 's', email: '', name: 'A B' });
    expect(() => service.parseUserInfo({ email: 'x@y.ca' })).toThrow();
  });

  it('stores the matched ICM contact in a portal_session cookie', async () => {
    siebel.getContactByBcscId.mockResolvedValue({ Id: '1-ABC' });
    const response = res();

    await service.createSession(user, response);

    const [name, token, options] = response.cookie.mock.calls[0] as [
      string,
      string,
      Record<string, unknown>,
    ];
    expect(name).toBe('portal_session');
    expect(options.httpOnly).toBe(true);
    const payload = await service.verifySession(reqWith({ [name]: token }));
    expect(payload?.contactId).toBe('1-ABC');
  });

  it('still logs in when ICM contact matching fails', async () => {
    siebel.getContactByBcscId.mockRejectedValue(new Error('siebel down'));
    const response = res();

    await service.createSession(user, response);

    const token = (response.cookie.mock.calls[0] as string[])[1];
    const payload = await service.verifySession(
      reqWith({ portal_session: token }),
    );
    expect(payload?.sub).toBe('bcsc-1');
    expect(payload?.contactId).toBeUndefined();
  });

  it('rejects caregiver tokens, tokens without the portal audience, and revoked tokens', async () => {
    const caregiverToken = jwt.sign(
      { ...user, userId: 'u1', jti: 'j1' },
      CAREGIVER_SECRET,
    );
    expect(
      await service.verifySession(reqWith({ portal_session: caregiverToken })),
    ).toBeNull();

    const noAudienceToken = jwt.sign({ ...user, jti: 'j2' }, PORTAL_SECRET);
    expect(
      await service.verifySession(reqWith({ portal_session: noAudienceToken })),
    ).toBeNull();

    siebel.getContactByBcscId.mockResolvedValue(null);
    const response = res();
    await service.createSession(user, response);
    const token = (response.cookie.mock.calls[0] as string[])[1];
    blacklist.isBlacklisted.mockResolvedValue(true);
    expect(
      await service.verifySession(reqWith({ portal_session: token })),
    ).toBeNull();
  });

  it('logout blacklists the token and clears only portal cookies', async () => {
    siebel.getContactByBcscId.mockResolvedValue(null);
    const created = res();
    await service.createSession(user, created);
    const token = (created.cookie.mock.calls[0] as string[])[1];

    const response = res();
    await service.endSession(reqWith({ portal_session: token }), response);

    expect(blacklist.blacklist).toHaveBeenCalledTimes(1);
    const cleared = response.clearCookie.mock.calls.map((c) => c[0] as string);
    expect(cleared).toEqual(['portal_session', 'portal_id_token']);
  });
});
