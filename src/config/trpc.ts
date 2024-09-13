import { initTRPC, TRPCError } from "@trpc/server";
import { CreateExpressContextOptions } from "@trpc/server/adapters/express";
import { prisma } from "./prisma";
import jwt from "jsonwebtoken";
import { ZodError } from "zod";

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

export const createContext = async ({
  req,
  res,
}: CreateExpressContextOptions) => {
  const getUserId = () => {
    if (req.cookies.token) {
      try {
        const verified = jwt.verify(req.cookies.token, JWT_SECRET) as {
          userId: string;
        };
        return verified.userId;
      } catch (err) {
        return null;
      }
    }
    return null;
  };

  const userId = getUserId();
  let user = null;

  if (userId) {
    user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, name: true, role: true },
    });
  }

  return {
    req,
    res,
    db: prisma,
    user,
  };
};

type Context = Awaited<ReturnType<typeof createContext>>;

const t = initTRPC.context<Context>().create({
  errorFormatter({ shape, error }) {
    return {
      ...shape,
      data: {
        ...shape.data,
        zodError:
          error.cause instanceof ZodError ? error.cause.flatten() : null,
      },
    };
  },
});

export const router = t.router;
export const publicProcedure = t.procedure;

const isAuthed = t.middleware(({ ctx, next }) => {
  if (!ctx.user) {
    throw new TRPCError({ code: "UNAUTHORIZED" });
  }
  return next({
    ctx: {
      ...ctx,
      user: ctx.user,
    },
  });
});

export const protectedProcedure = t.procedure.use(isAuthed);
