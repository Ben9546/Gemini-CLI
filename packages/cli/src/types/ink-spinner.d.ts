/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint import/no-default-export: 0 */

declare module 'ink-spinner' {
  import type { FC } from 'react';

  export interface SpinnerProps {
    /** Type of spinner to render (dots, line, etc.) */
    readonly type?: string;
  }

  /**
   * Ink-compatible spinner component that renders a variety of CLI spinners.
   *
   * NOTE: The upstream package returns an `InkElement` which is incompatible with
   * React 18+ type definitions. We re-declare it here as a standard React
   * functional component so that it can be consumed in JSX while preserving
   * type-safety.
   */
  export const Spinner: FC<SpinnerProps>;

  export default Spinner;
}