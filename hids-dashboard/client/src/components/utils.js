/**
 * Utility function for merging class names (similar to shadcn's cn function)
 * This combines class names and handles conditional classes properly
 */
export function cn(...classes) {
  return classes.filter(Boolean).join(' ');
}
