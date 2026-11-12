// Hostile analysis-thread entry: allocates until the heap limit is hit.
const hoard: number[][] = [];
for (;;) hoard.push(new Array(1_000_000).fill(Math.random()));
