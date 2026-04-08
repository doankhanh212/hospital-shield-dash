interface PageHeaderProps {
  title: string;
  description: string;
  actions?: React.ReactNode;
}

const PageHeader = ({ title, description, actions }: PageHeaderProps) => (
  <div className="page-header flex items-start justify-between">
    <div>
      <h2 className="page-title">{title}</h2>
      <p className="page-description">{description}</p>
    </div>
    {actions && <div className="flex items-center gap-2">{actions}</div>}
  </div>
);

export default PageHeader;
