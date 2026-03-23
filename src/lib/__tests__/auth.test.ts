import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import * as jose from "jose";
import { cookies } from "next/headers";
import { NextRequest } from "next/server";

vi.mock("next/headers");
vi.mock("jose");

import {
  createSession,
  getSession,
  deleteSession,
  verifySession,
  SessionPayload,
} from "@/lib/auth";

describe("Auth Functions", () => {
  const mockUserId = "user-123";
  const mockEmail = "test@example.com";
  const mockToken = "mock.jwt.token";

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe("createSession", () => {
    it("should create a session with valid inputs", async () => {
      const mockCookieStore = {
        set: vi.fn(),
      };
      vi.mocked(cookies).mockResolvedValue(mockCookieStore as any);
      vi.mocked(jose.SignJWT).mockImplementation(() => ({
        setProtectedHeader: vi.fn().mockReturnThis(),
        setExpirationTime: vi.fn().mockReturnThis(),
        setIssuedAt: vi.fn().mockReturnThis(),
        sign: vi.fn().mockResolvedValue(mockToken),
      } as any));

      await createSession(mockUserId, mockEmail);

      expect(mockCookieStore.set).toHaveBeenCalledWith(
        "auth-token",
        mockToken,
        expect.objectContaining({
          httpOnly: true,
          sameSite: "lax",
          path: "/",
        })
      );
    });

    it("should set secure cookie in production", async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = "production";

      const mockCookieStore = {
        set: vi.fn(),
      };
      vi.mocked(cookies).mockResolvedValue(mockCookieStore as any);
      vi.mocked(jose.SignJWT).mockImplementation(() => ({
        setProtectedHeader: vi.fn().mockReturnThis(),
        setExpirationTime: vi.fn().mockReturnThis(),
        setIssuedAt: vi.fn().mockReturnThis(),
        sign: vi.fn().mockResolvedValue(mockToken),
      } as any));

      await createSession(mockUserId, mockEmail);

      expect(mockCookieStore.set).toHaveBeenCalledWith(
        "auth-token",
        mockToken,
        expect.objectContaining({
          secure: true,
        })
      );

      process.env.NODE_ENV = originalEnv;
    });

    it("should set non-secure cookie in development", async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = "development";

      const mockCookieStore = {
        set: vi.fn(),
      };
      vi.mocked(cookies).mockResolvedValue(mockCookieStore as any);
      vi.mocked(jose.SignJWT).mockImplementation(() => ({
        setProtectedHeader: vi.fn().mockReturnThis(),
        setExpirationTime: vi.fn().mockReturnThis(),
        setIssuedAt: vi.fn().mockReturnThis(),
        sign: vi.fn().mockResolvedValue(mockToken),
      } as any));

      await createSession(mockUserId, mockEmail);

      expect(mockCookieStore.set).toHaveBeenCalledWith(
        "auth-token",
        mockToken,
        expect.objectContaining({
          secure: false,
        })
      );

      process.env.NODE_ENV = originalEnv;
    });

    it("should set expiration date 7 days from now", async () => {
      const mockCookieStore = {
        set: vi.fn(),
      };
      vi.mocked(cookies).mockResolvedValue(mockCookieStore as any);
      vi.mocked(jose.SignJWT).mockImplementation(() => ({
        setProtectedHeader: vi.fn().mockReturnThis(),
        setExpirationTime: vi.fn().mockReturnThis(),
        setIssuedAt: vi.fn().mockReturnThis(),
        sign: vi.fn().mockResolvedValue(mockToken),
      } as any));

      const beforeCreation = Date.now();
      await createSession(mockUserId, mockEmail);
      const afterCreation = Date.now();

      const callArgs = mockCookieStore.set.mock.calls[0][2];
      const expiresAt = callArgs.expires as Date;
      const expirationTime = expiresAt.getTime();

      const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;
      expect(expirationTime).toBeGreaterThanOrEqual(beforeCreation + sevenDaysMs);
      expect(expirationTime).toBeLessThanOrEqual(afterCreation + sevenDaysMs);
    });
  });

  describe("getSession", () => {
    it("should return null when no token is present", async () => {
      const mockCookieStore = {
        get: vi.fn().mockReturnValue(undefined),
      };
      vi.mocked(cookies).mockResolvedValue(mockCookieStore as any);

      const session = await getSession();

      expect(session).toBeNull();
    });

    it("should return session payload for valid token", async () => {
      const mockPayload: SessionPayload = {
        userId: mockUserId,
        email: mockEmail,
        expiresAt: new Date(),
      };

      const mockCookieStore = {
        get: vi.fn().mockReturnValue({ value: mockToken }),
      };
      vi.mocked(cookies).mockResolvedValue(mockCookieStore as any);
      vi.mocked(jose.jwtVerify).mockResolvedValue({
        payload: mockPayload,
      } as any);

      const session = await getSession();

      expect(session).toEqual(mockPayload);
    });

    it("should return null for invalid token", async () => {
      const mockCookieStore = {
        get: vi.fn().mockReturnValue({ value: mockToken }),
      };
      vi.mocked(cookies).mockResolvedValue(mockCookieStore as any);
      vi.mocked(jose.jwtVerify).mockRejectedValue(new Error("Invalid token"));

      const session = await getSession();

      expect(session).toBeNull();
    });

    it("should return null for expired token", async () => {
      const mockCookieStore = {
        get: vi.fn().mockReturnValue({ value: mockToken }),
      };
      vi.mocked(cookies).mockResolvedValue(mockCookieStore as any);
      vi.mocked(jose.jwtVerify).mockRejectedValue(
        new Error("Token expired")
      );

      const session = await getSession();

      expect(session).toBeNull();
    });
  });

  describe("deleteSession", () => {
    it("should delete the auth token cookie", async () => {
      const mockCookieStore = {
        delete: vi.fn(),
      };
      vi.mocked(cookies).mockResolvedValue(mockCookieStore as any);

      await deleteSession();

      expect(mockCookieStore.delete).toHaveBeenCalledWith("auth-token");
      expect(mockCookieStore.delete).toHaveBeenCalledTimes(1);
    });
  });

  describe("verifySession", () => {
    it("should return null when no token is present in request", async () => {
      const mockRequest = {
        cookies: {
          get: vi.fn().mockReturnValue(undefined),
        },
      } as unknown as NextRequest;

      const session = await verifySession(mockRequest);

      expect(session).toBeNull();
    });

    it("should return session payload for valid token in request", async () => {
      const mockPayload: SessionPayload = {
        userId: mockUserId,
        email: mockEmail,
        expiresAt: new Date(),
      };

      const mockRequest = {
        cookies: {
          get: vi.fn().mockReturnValue({ value: mockToken }),
        },
      } as unknown as NextRequest;

      vi.mocked(jose.jwtVerify).mockResolvedValue({
        payload: mockPayload,
      } as any);

      const session = await verifySession(mockRequest);

      expect(session).toEqual(mockPayload);
    });

    it("should return null for invalid token in request", async () => {
      const mockRequest = {
        cookies: {
          get: vi.fn().mockReturnValue({ value: mockToken }),
        },
      } as unknown as NextRequest;

      vi.mocked(jose.jwtVerify).mockRejectedValue(new Error("Invalid token"));

      const session = await verifySession(mockRequest);

      expect(session).toBeNull();
    });

    it("should verify JWT with correct algorithm", async () => {
      const mockPayload: SessionPayload = {
        userId: mockUserId,
        email: mockEmail,
        expiresAt: new Date(),
      };

      const mockRequest = {
        cookies: {
          get: vi.fn().mockReturnValue({ value: mockToken }),
        },
      } as unknown as NextRequest;

      vi.mocked(jose.jwtVerify).mockResolvedValue({
        payload: mockPayload,
      } as any);

      await verifySession(mockRequest);

      const expectedSecret = new TextEncoder().encode(
        process.env.JWT_SECRET || "development-secret-key"
      );

      expect(jose.jwtVerify).toHaveBeenCalledWith(
        mockToken,
        expectedSecret
      );
    });
  });

  describe("SessionPayload interface", () => {
    it("should have required properties", () => {
      const payload: SessionPayload = {
        userId: "123",
        email: "test@example.com",
        expiresAt: new Date(),
      };

      expect(payload).toHaveProperty("userId");
      expect(payload).toHaveProperty("email");
      expect(payload).toHaveProperty("expiresAt");
    });
  });
});
