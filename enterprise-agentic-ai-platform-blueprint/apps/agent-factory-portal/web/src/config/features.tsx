// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { createContext, useContext } from 'react';

/** Feature switches from the runtime configuration, for components that only need to read them. */
export interface PortalFeatures {
  /** True when the governed registration and approval screens are enabled. */
  governedActions: boolean;
}

const FeaturesContext = createContext<PortalFeatures>({ governedActions: false });

export const FeaturesProvider = FeaturesContext.Provider;

export function useFeatures(): PortalFeatures {
  return useContext(FeaturesContext);
}
