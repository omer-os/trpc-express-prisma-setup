import express from "express";
import * as trpcExpress from "@trpc/server/adapters/express";
import { renderTrpcPanel } from "trpc-panel";
import cookieParser from "cookie-parser";
import cors from "cors";
import { appRouter } from "./routers";
import { createContext } from "./config/trpc";

const app = express();

const corsOptions = {
  origin: ["http://localhost:3000", "http://localhost:4000"],
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

// Enable CORS
app.use(cors(corsOptions));
// Parse cookies
app.use(cookieParser());
app.options("*", cors(corsOptions));

// trpc routers are all mounted under /trpc
app.use(
  "/trpc",
  trpcExpress.createExpressMiddleware({
    router: appRouter,
    createContext,
  })
);

// tRPC panel where you can test queries
app.use("/panel", (_, res) => {
  return res.send(
    renderTrpcPanel(appRouter, { url: "http://localhost:4000/trpc" })
  );
});

// Starting the server
app.listen(4000, () => {
  console.log("Server running on http://localhost:4000");
  if (process.env.NODE_ENV === "development") {
    console.log("tRPC playground available at http://localhost:4000/panel");
  }
});
