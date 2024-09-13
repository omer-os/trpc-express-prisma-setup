import { router } from "../config/trpc";
import { authRouter } from "./auth.trpc";

// Combine all routers
export const appRouter = router({
  auth: authRouter,

  // Add more routers here
  // test: testRouter,
});

export type AppRouter = typeof appRouter;
