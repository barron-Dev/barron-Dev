import { NextRequest, NextResponse } from "next/server";

const HOSTS: Record<string, "surface" | "customer" | "developer" | "kontrol"> = {
  "cyclothone.online": "surface",
  "www.cyclothone.online": "surface",
  "customers.cyclothone.online": "customer",
  "developers.cyclothone.online": "developer",
  "kontrol-plane.cyclothone.online": "kontrol",
};

export function middleware(req: NextRequest) {
  const host = req.headers.get("host")?.split(":")[0]?.toLowerCase() ?? "";
  const surface = HOSTS[host];
  if (!surface) return NextResponse.next();

  const p = req.nextUrl.pathname;
  if (p.startsWith("/_next") || p.startsWith("/api")) return NextResponse.next();

  if (p.startsWith("/surface") || p.startsWith("/customer") || p.startsWith("/developers") || p.startsWith("/kontrol")) {
    return NextResponse.next();
  }

  // Public platform map is a real root route on the public surface.
  if (p === "/platform") return NextResponse.next();

  if (p === "/login" || p === "/register" || p === "/auth/callback" || p === "/request-service" || p.startsWith("/invitations/")) {
    return NextResponse.next();
  }

  const u = req.nextUrl.clone();

  if (surface === "surface") {
    u.pathname = "/surface" + (p === "/" ? "" : p);
    return NextResponse.rewrite(u);
  }

  if (surface === "customer") {
    if (p === "/") {
      u.pathname = "/login";
      return NextResponse.rewrite(u);
    }
    u.pathname = "/customer" + (p === "/" ? "/overview" : p);
    return NextResponse.rewrite(u);
  }

  if (surface === "developer") {
    u.pathname = "/developers" + (p === "/" ? "" : p);
    return NextResponse.rewrite(u);
  }

  if (surface === "kontrol") return NextResponse.next();

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
