import { Link } from "@tanstack/react-router";
import { Compass } from "lucide-react";
import { EmptyState } from "../ui";

export function NotFoundPage() {
  return (
    <EmptyState icon={<Compass />} title="Page not found" action={<Link to="/" className="text-[13px] text-accent hover:underline">Go to the portal home</Link>}>
      The address may be mistyped, or the page has moved.
    </EmptyState>
  );
}
