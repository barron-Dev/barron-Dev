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

  // Keep canonical internal route prefixes addressable without another rewrite.
  if (p.startsWith("/surface") || p.startsWith("/customer") || p.startsWith("/developers") || p.startsWith("/kontrol")) {
    return NextResponse.next();
  }

  const u = req.nextUrl.clone();

  if (surface === "surface") {
    u.pathname = "/surface" + (p === "/" ? "" : p);
    return NextResponse.rewrite(u);
  }

  if (surface === "customer") {
    // Customer subdomain exposes clean customer URLs while the app keeps
    // customer routes under /customer/* internally.
    u.pathname = "/customer" + (p === "/" ? "/overview" : p);
    return NextResponse.rewrite(u);
  }

  if (surface === "developer") {
    u.pathname = "/developers" + (p === "/" ? "" : p);
    return NextResponse.rewrite(u);
  }

  // Kontrol is different: its operational modules already live at root
  // paths (/detection, /response, /intelligence/*, ...). Do not prefix them
  // with /kontrol or the catch-all service routes become unreachable.
  if (surface === "kontrol") return NextResponse.next();

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
