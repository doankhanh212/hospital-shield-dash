import { useTheme } from '@/hooks/useTheme';

/** Returns consistent chart theme styles based on CSS variables */
export const useChartTheme = () => {
  const { theme } = useTheme();
  
  return {
    tooltipStyle: {
      backgroundColor: 'hsl(var(--tooltip-bg))',
      border: '1px solid hsl(var(--tooltip-border))',
      borderRadius: '8px',
      color: 'hsl(var(--tooltip-text))',
      fontSize: '12px',
    },
    gridStroke: 'hsl(var(--grid-stroke))',
    axisStroke: 'hsl(var(--axis-stroke))',
    axisTick: { fontSize: 11, fill: 'hsl(var(--axis-stroke))' },
    legendStyle: { fontSize: '12px' },
    colors: {
      primary: 'hsl(var(--chart-1))',
      success: 'hsl(var(--chart-2))',
      warning: 'hsl(var(--chart-3))',
      critical: 'hsl(var(--chart-4))',
      purple: 'hsl(var(--chart-5))',
    },
  };
};
