import { NextRequest, NextResponse } from "next/server";
import { hash } from "bcryptjs";
import { prisma } from "@/lib/db";
import { classifyReferrer } from "@/lib/referrer";

export async function POST(req: NextRequest) {
  try {
    const { name, email, password, referrerUrl, utmSource, utmMedium, utmCampaign } = await req.json();

    if (!name || !email || !password) {
      return NextResponse.json(
        { error: "Name, email, and password are required" },
        { status: 400 }
      );
    }

    if (password.length < 8) {
      return NextResponse.json(
        { error: "Password must be at least 8 characters" },
        { status: 400 }
      );
    }

    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return NextResponse.json(
        { error: "An account with this email already exists" },
        { status: 400 }
      );
    }

    const hashedPassword = await hash(password, 12);

    // Classify the referrer source
    const referrerSource = utmSource || classifyReferrer(referrerUrl || "");

    const user = await prisma.user.create({
      data: {
        name,
        email,
        hashedPassword,
        referrerSource: referrerSource || null,
        referrerUrl: referrerUrl || null,
        utmSource: utmSource || null,
        utmMedium: utmMedium || null,
        utmCampaign: utmCampaign || null,
      },
    });

    return NextResponse.json(
      { message: "Account created successfully", userId: user.id },
      { status: 201 }
    );
  } catch {
    return NextResponse.json(
      { error: "Something went wrong. Please try again." },
      { status: 500 }
    );
  }
}
