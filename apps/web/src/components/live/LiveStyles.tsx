/**
 * Keyframes used only by the live scan view. Kept local (not in index.css) so the page owns them; the
 * global prefers-reduced-motion rule in index.css still collapses every one of them.
 */
const CSS = `
@keyframes vs-live-sweep { from { transform: translateX(-110%); } to { transform: translateX(260%); } }
@keyframes vs-live-ping { 0% { transform: scale(1); opacity: .55; } 80%, 100% { transform: scale(2.4); opacity: 0; } }
@keyframes vs-live-flow { to { background-position: 16px 0; } }
@keyframes vs-live-enter {
  from { opacity: 0; transform: translateY(-8px); background-color: var(--signal-soft); }
  60% { opacity: 1; transform: none; background-color: var(--signal-soft); }
  to { opacity: 1; transform: none; background-color: transparent; }
}
@keyframes vs-live-bump { 0% { transform: translateY(0); } 25% { transform: translateY(-3px); } 100% { transform: translateY(0); } }
@keyframes vs-live-countdown { from { transform: scaleX(1); } to { transform: scaleX(0); } }
.vs-live-flow {
  background-image: linear-gradient(to right, var(--signal) 50%, transparent 50%);
  background-size: 8px 2px;
  animation: vs-live-flow .6s linear infinite;
}
`;

export function LiveStyles() {
  return <style>{CSS}</style>;
}
