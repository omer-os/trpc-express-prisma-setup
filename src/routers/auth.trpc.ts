import { router, publicProcedure, protectedProcedure } from "../config/trpc";
import { z } from "zod";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { TRPCError } from "@trpc/server";
import { Role } from "@prisma/client";

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";
const JWT_REFRESH_SECRET =
  process.env.JWT_REFRESH_SECRET || "your-refresh-secret-key";

const createTokens = (userId: string) => {
  const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: "15m" });
  const refreshToken = jwt.sign({ userId }, JWT_REFRESH_SECRET, {
    expiresIn: "7d",
  });
  return { token, refreshToken };
};

// setTokenCookies sets the token and refresh token as cookies in the response so that the client can store them in the browser.
const setTokenCookies = (res: any, token: string, refreshToken: string) => {
  res.cookie("token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    maxAge: 15 * 60 * 1000, // 15 minutes
  });
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });
};

export const authRouter = router({
  // Register a new user, hash the password, and return the user, if the email is admin@gmail.com and the environment is not production, set the role to ADMIN
  register: publicProcedure
    .input(
      z.object({
        email: z.string().email(),
        password: z.string().min(6),
        name: z.string(),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const { email, password, name } = input;
      const hashedPassword = await bcrypt.hash(password, 10);

      const role =
        email === "admin@gmail.com" && process.env.NODE_ENV !== "production"
          ? Role.ADMIN
          : Role.USER;

      const user = await ctx.db.user.create({
        data: {
          email,
          password: hashedPassword,
          name,
          role,
        },
      });

      return {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
        },
      };
    }),

  login: publicProcedure
    .input(
      z.object({
        email: z.string().email(),
        password: z.string(),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const { email, password } = input;
      const user = await ctx.db.user.findUnique({ where: { email } });

      if (!user || !(await bcrypt.compare(password, user.password))) {
        throw new TRPCError({
          code: "UNAUTHORIZED",
          message: "Invalid email or password",
        });
      }

      const { token, refreshToken } = createTokens(user.id);
      setTokenCookies(ctx.res, token, refreshToken);

      return {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
        },
      };
    }),

  logout: protectedProcedure.mutation(({ ctx }) => {
    ctx.res.clearCookie("token");
    ctx.res.clearCookie("refreshToken");
    return { success: true };
  }),

  refreshToken: publicProcedure.query(({ ctx }) => {
    const refreshToken = ctx.req.cookies.refreshToken;

    if (!refreshToken) {
      throw new TRPCError({
        code: "UNAUTHORIZED",
        message: "No refresh token provided",
      });
    }

    try {
      const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET) as {
        userId: string;
      };
      const { token, refreshToken: newRefreshToken } = createTokens(
        decoded.userId
      );
      setTokenCookies(ctx.res, token, newRefreshToken);
      return { success: true };
    } catch (error) {
      throw new TRPCError({
        code: "UNAUTHORIZED",
        message: "Invalid refresh token",
      });
    }
  }),

  me: protectedProcedure.query(async ({ ctx }) => {
    const user = await ctx.db.user.findUnique({
      where: { id: ctx.user.id },
      select: { id: true, email: true, name: true, role: true },
    });

    if (!user) {
      throw new TRPCError({
        code: "NOT_FOUND",
        message: "User not found",
      });
    }

    return { user };
  }),
});
