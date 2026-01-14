import type { Metadata } from "next";
import { Inter, Poppins } from "next/font/google";
import "./globals.css";
import { ThemeProvider } from "next-themes";
import { Toaster } from "@/components/ui/sonner";
import ThemeToggle from "@/components/theme-toggle";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
});

const poppins = Poppins({
  variable: "--font-poppins",
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
});

export const metadata: Metadata = {
  title: "AI Powered Antivirus with Anomaly Detection",
  description: "AI-powered antivirus dashboard",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${inter.variable} ${poppins.variable} antialiased`} suppressHydrationWarning>
        <ThemeProvider attribute="class" defaultTheme="system" enableSystem>
          <div className="min-h-dvh bg-background/50 text-foreground">
            <header className="sticky top-0 z-50 border-b border-border/50 bg-background/40 backdrop-blur-md shadow-sm">
              <div className="mx-auto flex max-w-screen-2xl items-center justify-between gap-4 px-4 py-4">
                <div className="flex-1" /> {/* Spacer */}
                <div className="text-xl font-semibold tracking-tight text-center" style={{ fontFamily: 'var(--font-poppins)' }}>AI Powered Antivirus with Anomaly Detection</div>
                <div className="flex flex-1 items-center justify-end gap-3">
                  <ThemeToggle />
                </div>
              </div>
            </header>
            <main className="mx-auto max-w-screen-2xl p-4 md:p-6 lg:p-8">{children}</main>
          </div>
          <Toaster richColors position="top-right" />
        </ThemeProvider>
      </body>
    </html>
  );
}
