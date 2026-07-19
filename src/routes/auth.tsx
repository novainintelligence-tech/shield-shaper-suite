import { createFileRoute, Link } from "@tanstack/react-router";
import { ShieldCheck } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { toast } from "sonner";

export const Route = createFileRoute("/auth")({
  head: () => ({
    meta: [
      { title: "Sign in · NOVAIN Security Lab" },
      { name: "description", content: "Sign in to the NOVAIN Security Lab console." },
    ],
  }),
  component: AuthPage,
});

function AuthPage() {
  const [mode, setMode] = useState<"signin" | "signup">("signin");

  return (
    <div className="grid-bg flex min-h-[calc(100vh-3.5rem)] items-center justify-center px-4">
      <Card className="w-full max-w-md panel">
        <CardHeader>
          <div className="mb-2 flex h-10 w-10 items-center justify-center rounded-md bg-primary/15 ring-1 ring-primary/40">
            <ShieldCheck className="h-5 w-5 text-primary" />
          </div>
          <CardTitle className="text-xl">
            {mode === "signin" ? "Sign in to NSL" : "Create your NSL account"}
          </CardTitle>
          <p className="text-sm text-muted-foreground">
            {mode === "signin"
              ? "Access your security console."
              : "Provision a new workspace for validation runs."}
          </p>
        </CardHeader>
        <CardContent>
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              toast.info("Authentication is mocked", {
                description: "Enable Lovable Cloud to wire real auth (email + MFA).",
              });
            }}
          >
            {mode === "signup" && (
              <div className="space-y-2">
                <Label htmlFor="name">Full name</Label>
                <Input id="name" placeholder="Alex Rivera" />
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor="email">Work email</Label>
              <Input id="email" type="email" placeholder="you@company.com" />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input id="password" type="password" placeholder="••••••••" />
            </div>
            {mode === "signin" && (
              <div className="space-y-2">
                <Label htmlFor="totp">TOTP code</Label>
                <Input id="totp" inputMode="numeric" maxLength={6} placeholder="123 456" className="font-mono tracking-widest" />
              </div>
            )}
            <Button className="w-full" type="submit">
              {mode === "signin" ? "Sign in" : "Create account"}
            </Button>
          </form>

          <div className="mt-4 flex items-center justify-between text-xs text-muted-foreground">
            <button
              type="button"
              className="underline-offset-2 hover:text-foreground hover:underline"
              onClick={() => setMode(mode === "signin" ? "signup" : "signin")}
            >
              {mode === "signin" ? "Create an account" : "Have an account? Sign in"}
            </button>
            <Link to="/" className="underline-offset-2 hover:text-foreground hover:underline">
              Continue as guest
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
