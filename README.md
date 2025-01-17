﻿# Express, tRPC, and Prisma Example

This is a simple example of how to use Express, tRPC, and Prisma ORM together. It includes an authentication router with endpoints for login, registration, logout, and token refresh. The schema is defined in the `prisma/schema.prisma` file. this code also includes validation with zod.

## Getting Started

1. Clone the repository.
2. Install dependencies using `pnpm install`.
3. Add the required environment variables.
4. Push the schema to the database with `pnpm prisma db push`.
5. Generate the Prisma client with `pnpm prisma generate`.
6. Start the server with `pnpm dev`.
