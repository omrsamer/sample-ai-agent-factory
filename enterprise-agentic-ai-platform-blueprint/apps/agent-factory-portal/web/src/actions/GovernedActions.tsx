// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { Route, Routes } from 'react-router-dom';
import Approvals from './Approvals';
import RegistrationDetail from './RegistrationDetail';
import RegistrationForm from './RegistrationForm';
import RegistrationsList from './RegistrationsList';

/**
 * Entry point of the governed registration and approval feature. The application loads this
 * module only when `features.governedActions` is true; nothing outside this folder imports from
 * it except through that one dynamic import.
 */
export default function GovernedActions() {
  return (
    <Routes>
      <Route index element={<RegistrationsList />} />
      <Route path="new" element={<RegistrationForm />} />
      <Route path=":id" element={<RegistrationDetail />} />
      <Route path=":id/edit" element={<RegistrationForm />} />
    </Routes>
  );
}

export { Approvals };
