import { AlertTriangle, RotateCw } from 'lucide-react';
import { Component, type ErrorInfo, type ReactNode } from 'react';
import { M3Button, M3SurfaceCard } from './md3';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  errorText: string | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = {
    hasError: false,
    errorText: null,
  };

  static getDerivedStateFromError(error: Error): State {
    return {
      hasError: true,
      errorText: error?.message || 'Непредвиденная ошибка отображения интерфейса',
    };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('AURA VPN UI ErrorBoundary:', error, info.componentStack);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex h-full w-full items-center justify-center bg-[var(--md-surface)] p-6 text-[var(--md-on-surface)]">
          <M3SurfaceCard className="w-full max-w-md p-6 text-center">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-[var(--md-error-container)] text-[var(--md-error)]">
              <AlertTriangle className="h-6 w-6" />
            </div>
            <h1 className="mt-4 font-display text-base font-bold">
              Произошёл сбой интерфейса
            </h1>
            <p className="mt-1.5 text-xs leading-relaxed text-[var(--md-on-surface-variant)]">
              {this.state.errorText}
            </p>
            <div className="mt-5 flex justify-center">
              <M3Button
                variant="filled"
                leadingIcon={<RotateCw className="h-4 w-4" />}
                onClick={() => window.location.reload()}
              >
                Перезагрузить интерфейс
              </M3Button>
            </div>
          </M3SurfaceCard>
        </div>
      );
    }
    return this.props.children;
  }
}
