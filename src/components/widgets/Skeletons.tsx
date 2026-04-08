interface TableSkeletonProps {
  rows?: number;
  cols?: number;
}

export const TableSkeleton = ({ rows = 5, cols = 6 }: TableSkeletonProps) => (
  <div className="rounded-lg border border-border bg-card overflow-hidden">
    <div className="border-b border-border px-4 py-3 flex gap-4">
      {Array.from({ length: cols }).map((_, i) => (
        <div key={i} className="h-3 skeleton-shimmer rounded flex-1" />
      ))}
    </div>
    {Array.from({ length: rows }).map((_, r) => (
      <div key={r} className="border-b border-border/50 px-4 py-3.5 flex gap-4">
        {Array.from({ length: cols }).map((_, c) => (
          <div key={c} className="h-3 skeleton-shimmer rounded flex-1" style={{ maxWidth: c === 0 ? '120px' : undefined }} />
        ))}
      </div>
    ))}
  </div>
);

export const CardSkeleton = () => (
  <div className="rounded-lg border border-border bg-card p-5 space-y-3">
    <div className="flex items-center justify-between">
      <div className="h-3 w-24 skeleton-shimmer rounded" />
      <div className="h-10 w-10 skeleton-shimmer rounded-lg" />
    </div>
    <div className="h-7 w-16 skeleton-shimmer rounded" />
    <div className="h-2 w-20 skeleton-shimmer rounded" />
  </div>
);

export const ChartSkeleton = () => (
  <div className="rounded-lg border border-border bg-card p-5">
    <div className="h-4 w-32 skeleton-shimmer rounded mb-6" />
    <div className="flex items-end gap-2 h-[200px]">
      {[60, 80, 45, 90, 70, 55, 85, 40].map((h, i) => (
        <div key={i} className="flex-1 skeleton-shimmer rounded-t" style={{ height: `${h}%` }} />
      ))}
    </div>
  </div>
);

export const StatCardsSkeleton = () => (
  <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
    {[1, 2, 3, 4].map(i => <CardSkeleton key={i} />)}
  </div>
);
