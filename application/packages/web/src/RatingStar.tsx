import { Star } from './icons';

/**
 * The gold star of a rating ask. On a light palette `pn-rating-star` gives it
 * an amber-700 edge in index.css, because the gold alone does not carry on a
 * light surface. A module of its own, so the account screens on the boot path
 * do not pull in the rate links.
 */
export function RatingStar({ size }: { size: number }) {
  return <Star size={size} weight="fill" className="pn-rating-star shrink-0 text-amber-400" aria-hidden="true" />;
}
