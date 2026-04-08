import { type LucideIcon, SearchX } from 'lucide-react';

interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description: string;
  action?: React.ReactNode;
}

const EmptyState = ({ icon: Icon = SearchX, title, description, action }: EmptyStateProps) => (
  <div className="flex flex-col items-center justify-center py-16 px-4">
    <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-muted mb-4">
      <Icon size={24} className="text-muted-foreground" />
    </div>
    <h3 className="text-base font-semibold text-foreground">{title}</h3>
    <p className="mt-1 text-sm text-muted-foreground text-center max-w-sm">{description}</p>
    {action && <div className="mt-4">{action}</div>}
  </div>
);

export default EmptyState;
