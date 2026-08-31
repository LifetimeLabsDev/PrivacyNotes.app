import type { ReactNode } from 'react';
import { ArrowUpRight } from './icons';

export type ModalLink = {
  href: string;
  label: string;
  desc: string;
  rel: string;
  icon: ReactNode;
};

/**
 * The rows shared by the external-link surfaces: icon, label, description
 * and an external-arrow affordance. Lifted out of `LinksModal` when the
 * About modal grew a Rating tab, so the same list renders inside a modal
 * shell and inside a tab pane without the two drifting apart.
 */
export function LinksList({
  links,
  onLinkClick,
}: {
  links: readonly ModalLink[];
  /** Fired when a row is opened. The rating surfaces use it to record that
   *  the user acted, so the app never asks them again. */
  onLinkClick?: () => void;
}) {
  return (
    <div className="space-y-2">
      {links.map((l) => (
        <a
          key={l.href}
          href={l.href}
          target="_blank"
          rel={l.rel}
          onClick={onLinkClick}
          className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-surface-1 transition group"
        >
          <span className="text-neutral-400 group-hover:text-accent transition">{l.icon}</span>
          <span className="min-w-0">
            <span className="block text-sm font-medium text-accent">{l.label}</span>
            <span className="block text-xs text-neutral-500">{l.desc}</span>
          </span>
          <ArrowUpRight className="ms-auto shrink-0 text-neutral-300 dark:text-neutral-700 group-hover:text-accent transition" />
        </a>
      ))}
    </div>
  );
}
